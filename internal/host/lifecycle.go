package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/fsutil"
	"nx-sync-server/internal/port"
	"nx-sync-server/internal/probe"
	"nx-sync-server/internal/protocol"
	"nx-sync-server/internal/release"
	"nx-sync-server/internal/store"
	"nx-sync-server/internal/tlsutil"
	"nx-sync-server/internal/updates"
)

// Layout roots only the component's fixed paths. Production always uses Root=/.
// Tests use a temporary root and a fake Runner; the CLI has no root override.
type Layout struct{ Root string }

func (l Layout) path(p string) string { return filepath.Join(l.Root, p) }
func (l Layout) app() string          { return l.path("/opt/nx-syncd") }
func (l Layout) meta() string         { return l.path("/var/lib/nx-syncctl") }
func (l Layout) data() string         { return l.path("/var/lib/nx-syncd") }
func (l Layout) conf() string         { return l.path("/etc/nx-syncd") }
func (l Layout) manifest() string     { return filepath.Join(l.meta(), "install.json") }
func (l Layout) journal() string      { return filepath.Join(l.meta(), "operation.json") }
func (l Layout) service() string      { return l.path("/etc/systemd/system/nx-syncd.service") }
func (l Layout) socket() string       { return l.path("/etc/systemd/system/nx-syncd.socket") }
func (l Layout) binaryDir(sequence uint64) string {
	return filepath.Join(l.app(), "releases", strconv.FormatUint(sequence, 10))
}

type Manifest struct {
	Format              int               `json:"format"`
	InstallationID      string            `json:"installation_id"`
	State               string            `json:"state"`
	Config              config.Config     `json:"config"`
	Pin                 string            `json:"pin"`
	TrustKey            string            `json:"trust_key"`
	Sequence            uint64            `json:"sequence,string"`
	HighestSequence     uint64            `json:"highest_sequence,string"`
	Version             string            `json:"version"`
	Unsigned            bool              `json:"unsigned,omitempty"`
	ReleaseMetadata     *release.Metadata `json:"release_metadata,omitempty"`
	PreviousRelease     *PreviousRelease  `json:"previous_release,omitempty"`
	AutoPort            bool              `json:"auto_port"`
	FirewallZone        string            `json:"firewall_zone"`
	AllowManualFirewall bool              `json:"allow_manual_firewall"`
	Rule                *Rule             `json:"rule,omitempty"`
	UID                 int               `json:"uid"`
	GID                 int               `json:"gid"`
	UserCreated         bool              `json:"user_created"`
	ServiceHash         string            `json:"service_hash"`
	SocketHash          string            `json:"socket_hash"`
	PreviousServiceHash string            `json:"previous_service_hash,omitempty"`
	PreviousSocketHash  string            `json:"previous_socket_hash,omitempty"`
	DirectoryIDs        map[string]string `json:"directory_ids,omitempty"`
}

type Operation struct {
	Kind               string           `json:"kind"`
	Stage              string           `json:"stage"`
	Bundle             string           `json:"bundle,omitempty"`
	Release            release.Metadata `json:"release"`
	Unsigned           bool             `json:"unsigned,omitempty"`
	Previous           *PreviousRelease `json:"previous_release,omitempty"`
	RollbackOnFailure  bool             `json:"rollback_on_failure,omitempty"`
	Purge              bool             `json:"purge,omitempty"`
	ExpectedGeneration string           `json:"expected_generation,omitempty"`
	TargetGeneration   string           `json:"target_generation,omitempty"`
}

type PreviousRelease struct {
	Metadata release.Metadata `json:"metadata"`
	Unsigned bool             `json:"unsigned"`
}

type InstallOptions struct {
	Bundle, TrustKey, TLSHost, Bind, FirewallZone string
	Port                                          int
	MemoryBytes                                   int64
	BlockWebPorts, AllowManualFirewall            bool
	AllowUnsigned                                 bool
}

type UpdateOptions struct {
	Bundle            string
	AllowUnsigned     bool
	RollbackOnFailure bool
	ExpectedPolicy    *UpdatePolicy
}

type Manager struct {
	Layout Layout
	Runner Runner
	// Probe is replaceable only in local tests. Production uses pinned local HTTPS.
	Probe func(context.Context, string, string, string) (probe.Result, error)
}

func New() *Manager {
	return &Manager{Layout: Layout{Root: "/"}, Runner: Commands{}, Probe: probe.Local}
}

func (m *Manager) save(man Manifest) error { return fsutil.WriteJSON(m.Layout.manifest(), man, 0600) }
func (m *Manager) saveOperation(op Operation) error {
	return fsutil.WriteJSON(m.Layout.journal(), op, 0600)
}

func (m *Manager) directories(man *Manifest, record bool) error {
	if man.DirectoryIDs == nil {
		man.DirectoryIDs = map[string]string{}
	}
	for name, path := range map[string]string{"app": m.Layout.app(), "config": m.Layout.conf(), "data": m.Layout.data()} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("owned directory was replaced")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot verify owned directory identity")
		}
		identity := fmt.Sprintf("%d:%d", st.Dev, st.Ino)
		if previous := man.DirectoryIDs[name]; previous != "" && previous != identity {
			return errors.New("owned directory identity changed; refusing foreign path mutation")
		}
		if record {
			man.DirectoryIDs[name] = identity
		}
	}
	if record {
		return m.save(*man)
	}
	return nil
}

func (m *Manager) load() (Manifest, error) {
	var man Manifest
	if err := fsutil.ReadJSON(m.Layout.manifest(), &man, 128<<10); err != nil {
		return man, err
	}
	if man.Format != 1 || !protocol.ValidID(man.InstallationID) || man.Config.Database != filepath.Join(m.Layout.data(), "settings.sqlite") || man.Config.TLSKey != filepath.Join(m.Layout.conf(), "server.key") || man.Config.TLSCertificate != filepath.Join(m.Layout.data(), "tls", "server.pem") {
		return man, errors.New("invalid owned installation manifest")
	}
	if err := man.Config.Validate(); err != nil {
		return man, err
	}
	return man, nil
}

func (m *Manager) lock() (func(), error) {
	if err := secureDirectory(m.Layout.meta(), os.Geteuid(), os.Getegid(), 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(m.Layout.meta(), "operation.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("another administration operation is running")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

func secureDirectory(path string, uid, gid int, mode os.FileMode) error {
	// Parent symlinks are rejected too: chown/creation must not follow them.
	for parent := path; parent != "/" && parent != "."; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("installation directory contains a non-directory or symlink")
		}
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() && int(st.Uid) != uid || info.Mode().Perm()&0022 != 0 {
		return errors.New("installation directory has foreign ownership or write permissions")
	}
	if err = os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func limits(c config.Config) store.Limits {
	return store.Limits{EnvelopeBytes: c.MaxEnvelopeBytes, ProfileBytes: c.MaxProfileBytes, Devices: c.MaxDevices}
}

func (m *Manager) checkFresh(ctx context.Context) error {
	for _, p := range []string{m.Layout.app(), m.Layout.data(), m.Layout.conf(), m.Layout.service(), m.Layout.socket()} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("installation path already exists or cannot be inspected: %s", p)
		}
	}
	for _, unit := range []string{"nx-syncd.service", "nx-syncd.socket"} {
		output, err := m.Runner.Run(ctx, "systemctl", "show", unit, "--property=LoadState", "--value")
		if err != nil && status(err) != 4 {
			return err
		}
		if value := strings.TrimSpace(string(output)); value != "not-found" && value != "" {
			return errors.New("a foreign unit already uses the nx-syncd name")
		}
	}
	if _, err := m.Runner.Run(ctx, "getent", "passwd", "nx-syncd"); status(err) != 2 {
		return errors.New("service account already exists or cannot be inspected")
	}
	return nil
}

func (m *Manager) Install(ctx context.Context, o InstallOptions) (Manifest, error) {
	unlock, err := m.lock()
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()
	if _, err = os.Lstat(m.Layout.manifest()); !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, errors.New("installation metadata exists; use status or recover")
	}
	if err = m.checkFresh(ctx); err != nil {
		return Manifest{}, err
	}
	provider, err := DetectFirewall(ctx, m.Runner)
	if err != nil {
		return Manifest{}, err
	}
	if provider == "manual" && !o.AllowManualFirewall {
		return Manifest{}, errors.New("unsupported firewall: explicit manual ingress acknowledgement required before installation")
	}
	verified, err := release.Inspect(filepath.Join(o.Bundle, "release.json"), o.TrustKey, 0, time.Now(), o.AllowUnsigned)
	if err != nil {
		return Manifest{}, err
	}
	metadata := verified.Metadata
	if err = release.CheckArtifacts(o.Bundle, metadata); err != nil {
		return Manifest{}, err
	}
	if o.Bind == "" {
		o.Bind = "0.0.0.0"
	}
	if o.MemoryBytes == 0 {
		o.MemoryBytes = 256 << 20
	}
	l, err := port.Reserve(ctx, port.Policy{Host: o.Bind, Port: o.Port, BlockWebPorts: o.BlockWebPorts})
	if err != nil {
		return Manifest{}, err
	}
	listen := l.Addr().String()
	_ = l.Close() // Preview only; final bind belongs to systemd.
	c := config.Defaults()
	c.Listen = listen
	c.TLSHost = o.TLSHost
	c.MemoryBytes = o.MemoryBytes
	c.BlockWebPorts = o.BlockWebPorts
	c.Database = filepath.Join(m.Layout.data(), "settings.sqlite")
	c.TLSKey = filepath.Join(m.Layout.conf(), "server.key")
	c.TLSCertificate = filepath.Join(m.Layout.data(), "tls", "server.pem")
	if err = c.Validate(); err != nil {
		return Manifest{}, err
	}
	id, err := protocol.NewID()
	if err != nil {
		return Manifest{}, err
	}
	man := Manifest{Format: 1, InstallationID: id, State: "installing", Config: c, TrustKey: o.TrustKey, Sequence: metadata.Sequence, HighestSequence: metadata.Sequence, Version: metadata.Version, Unsigned: !verified.Signed, ReleaseMetadata: &metadata, AutoPort: o.Port == 0, FirewallZone: o.FirewallZone, AllowManualFirewall: o.AllowManualFirewall, UID: -1, GID: -1}
	bundle, err := filepath.Abs(o.Bundle)
	if err != nil {
		return Manifest{}, err
	}
	op := Operation{Kind: "install", Stage: "prepared", Bundle: bundle, Release: metadata, Unsigned: !verified.Signed}
	if err = m.save(man); err != nil {
		return man, err
	}
	if err = m.saveOperation(op); err != nil {
		return man, err
	}
	return m.install(ctx, man, op)
}

func (m *Manager) account(ctx context.Context, man *Manifest) error {
	output, err := m.Runner.Run(ctx, "getent", "passwd", "nx-syncd")
	if status(err) == 2 {
		if man.UID >= 0 {
			return errors.New("recorded service account disappeared")
		}
		if _, err = m.Runner.Run(ctx, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "nx-syncd"); err != nil {
			return err
		}
		man.UserCreated = true
		output, err = m.Runner.Run(ctx, "getent", "passwd", "nx-syncd")
	}
	if err != nil {
		return err
	}
	fields := strings.Split(strings.TrimSpace(string(output)), ":")
	if len(fields) != 7 || fields[0] != "nx-syncd" {
		return errors.New("invalid service account")
	}
	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(fields[3])
	if err != nil {
		return err
	}
	if uid <= 0 || gid <= 0 || man.UID >= 0 && (uid != man.UID || gid != man.GID) {
		return errors.New("service account identity changed")
	}
	man.UID = uid
	man.GID = gid
	return m.save(*man)
}

func (m *Manager) stage(bundle string, metadata release.Metadata) error {
	dir := m.Layout.binaryDir(metadata.Sequence)
	if err := secureDirectory(dir, os.Geteuid(), os.Getegid(), 0755); err != nil {
		return err
	}
	if err := release.CheckArtifacts(dir, metadata); err == nil {
		return nil
	}
	if err := release.CheckArtifacts(bundle, metadata); err != nil {
		return err
	}
	for _, a := range metadata.Artifacts {
		data, err := readRegular(filepath.Join(bundle, a.Name), a.Size)
		if err != nil {
			return err
		}
		if int64(len(data)) != a.Size || digest(data) != a.SHA256 {
			return errors.New("release changed while staging")
		}
		if err = fsutil.AtomicWrite(filepath.Join(dir, a.Name), data, 0755); err != nil {
			return err
		}
	}
	return release.CheckArtifacts(dir, metadata)
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("not a bounded regular file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	// Limits are applied to the actual opened file, not just a preceding stat.
	data, err := fsutil.ReadBounded(file, limit)
	return data, err
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func (m *Manager) link(sequence uint64) error {
	path := filepath.Join(m.Layout.app(), "current")
	temporary := filepath.Join(m.Layout.app(), ".next")
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink == 0 {
		return errors.New("current release pointer is not a symlink")
	}
	_ = os.Remove(temporary)
	if err := os.Symlink(filepath.Join("releases", strconv.FormatUint(sequence, 10)), temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	dir, err := os.Open(m.Layout.app())
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (m *Manager) install(ctx context.Context, man Manifest, op Operation) (Manifest, error) {
	if man.State != "installing" && man.State != "installed" {
		return man, errors.New("installation is not pending")
	}
	if err := m.directories(&man, false); err != nil {
		return man, err
	}
	if err := m.stage(op.Bundle, op.Release); err != nil {
		return man, err
	}
	if err := m.account(ctx, &man); err != nil {
		return man, err
	}
	for _, d := range []struct {
		path     string
		uid, gid int
		mode     os.FileMode
	}{
		{m.Layout.conf(), os.Geteuid(), man.GID, 0750}, {m.Layout.data(), man.UID, man.GID, 0750}, {filepath.Dir(man.Config.TLSCertificate), man.UID, man.GID, 0750},
	} {
		if err := secureDirectory(d.path, d.uid, d.gid, d.mode); err != nil {
			return man, err
		}
	}
	if err := m.directories(&man, true); err != nil {
		return man, err
	}
	if _, err := os.Lstat(man.Config.Database); errors.Is(err, os.ErrNotExist) {
		s, e := store.Create(ctx, man.Config.Database, limits(man.Config))
		if e != nil {
			return man, e
		}
		if e = s.Close(); e != nil {
			return man, e
		}
	} else if err != nil {
		return man, err
	}
	s, err := store.Open(ctx, man.Config.Database, limits(man.Config))
	if err != nil {
		return man, err
	}
	if err = s.Close(); err != nil {
		return man, err
	}
	if err = os.Chown(man.Config.Database, man.UID, man.GID); err != nil {
		return man, err
	}
	if _, err = os.Lstat(man.Config.TLSKey); errors.Is(err, os.ErrNotExist) {
		man.Pin, err = tlsutil.Create(man.Config.TLSKey, man.Config.TLSCertificate, man.Config.TLSHost, time.Now())
		if err != nil {
			return man, err
		}
	} else if err != nil {
		return man, err
	} else {
		if _, err = os.Lstat(man.Config.TLSCertificate); errors.Is(err, os.ErrNotExist) {
			if err = tlsutil.RestoreCertificate(man.Config.TLSKey, man.Config.TLSCertificate, man.Config.TLSHost, time.Now()); err != nil {
				return man, err
			}
		}
		if _, err = tlsutil.Load(man.Config.TLSKey, man.Config.TLSCertificate, man.Config.TLSHost); err != nil {
			return man, err
		}
		pin, err := tlsutil.ReadFingerprint(man.Config.TLSCertificate)
		if err != nil {
			return man, err
		}
		if man.Pin != "" && pin != man.Pin {
			return man, errors.New("TLS identity changed during installation")
		}
		man.Pin = pin
	}
	for _, p := range []string{man.Config.TLSKey, man.Config.TLSCertificate} {
		uid := os.Geteuid()
		if p == man.Config.TLSCertificate {
			uid = man.UID
		}
		if err = os.Chown(p, uid, man.GID); err != nil {
			return man, err
		}
		if err = os.Chmod(p, 0640); err != nil {
			return man, err
		}
	}
	if err = m.link(man.Sequence); err != nil {
		return man, err
	}
	if err = m.save(man); err != nil {
		return man, err
	}
	op.Stage = "files_prepared"
	if err = m.saveOperation(op); err != nil {
		return man, err
	}
	if err = m.startSocket(ctx, &man); err != nil {
		return man, err
	}
	if man.Rule == nil {
		provider, err := DetectFirewall(ctx, m.Runner)
		if err != nil {
			return man, err
		}
		if provider == "manual" && !man.AllowManualFirewall {
			return man, errors.New("unknown firewall: configure ingress manually and explicitly allow manual firewall")
		}
		_, portText, _ := net.SplitHostPort(man.Config.Listen)
		number, _ := strconv.Atoi(portText)
		rule, err := PlanRule(ctx, m.Runner, provider, man.FirewallZone, man.InstallationID, number)
		if err != nil {
			return man, err
		}
		man.Rule = &rule
		if err = m.save(man); err != nil {
			return man, err
		} // Persist intent before mutation.
	}
	if err = ApplyRule(ctx, m.Runner, man.Rule); err != nil {
		return man, err
	}
	if err = m.save(man); err != nil {
		return man, err
	}
	op.Stage = "firewall_prepared"
	if err = m.saveOperation(op); err != nil {
		return man, err
	}
	if err = m.start(ctx, man); err != nil {
		return man, err
	}
	if _, err = m.Runner.Run(ctx, "systemctl", "enable", "nx-syncd.socket", "nx-syncd.service"); err != nil {
		return man, err
	}
	man.State = "installed"
	if err = m.save(man); err != nil {
		return man, err
	}
	op.Stage = "complete"
	return man, m.saveOperation(op)
}

func (m *Manager) Status() (Manifest, Operation, error) {
	man, err := m.load()
	if err != nil {
		return man, Operation{}, err
	}
	var op Operation
	err = fsutil.ReadJSON(m.Layout.journal(), &op, 64<<10)
	return man, op, err
}

func (m *Manager) Recover(ctx context.Context) (Manifest, error) {
	unlock, err := m.lock()
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()
	man, op, err := m.Status()
	if err != nil {
		return man, err
	}
	if op.Stage == "complete" {
		return man, nil
	}
	switch op.Kind {
	case "install":
		return m.install(ctx, man, op)
	case "reset":
		return m.reset(ctx, man, op)
	case "uninstall":
		return m.uninstall(ctx, man, op)
	case "update":
		return m.update(ctx, man, op)
	case "rollback":
		return m.rollback(ctx, man, op)
	default:
		return man, errors.New("unsupported pending operation")
	}
}

func (m *Manager) checkIdle() (Manifest, error) {
	man, op, err := m.Status()
	if err != nil {
		return man, err
	}
	if op.Stage != "complete" || man.State != "installed" {
		return man, errors.New("installation has a pending operation; use recover")
	}
	return man, m.checkUnits(man)
}

func (m *Manager) Reset(ctx context.Context) (Manifest, error) {
	unlock, err := m.lock()
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()
	man, err := m.checkIdle()
	if err != nil {
		return man, err
	}
	s, err := store.Open(ctx, man.Config.Database, limits(man.Config))
	if err != nil {
		return man, err
	}
	id, err := s.Identity(ctx)
	closeErr := s.Close()
	if err != nil {
		return man, err
	}
	if closeErr != nil {
		return man, closeErr
	}
	target, err := protocol.NewID()
	if err != nil {
		return man, err
	}
	op := Operation{Kind: "reset", Stage: "prepared", ExpectedGeneration: id.Generation, TargetGeneration: target}
	if err = m.saveOperation(op); err != nil {
		return man, err
	}
	return m.reset(ctx, man, op)
}

func (m *Manager) reset(ctx context.Context, man Manifest, op Operation) (Manifest, error) {
	if err := m.stop(ctx, man); err != nil {
		return man, err
	}
	s, err := store.Open(ctx, man.Config.Database, limits(man.Config))
	if err != nil {
		return man, err
	}
	_, err = s.ResetGeneration(ctx, op.ExpectedGeneration, op.TargetGeneration)
	closeErr := s.Close()
	if err != nil {
		return man, err
	}
	if closeErr != nil {
		return man, closeErr
	}
	if err = os.RemoveAll(filepath.Join(m.Layout.meta(), "backups")); err != nil {
		return man, err
	}
	op.Stage = "database_reset"
	if err = m.saveOperation(op); err != nil {
		return man, err
	}
	if err = m.start(ctx, man); err != nil {
		return man, err
	}
	op.Stage = "complete"
	return man, m.saveOperation(op)
}

func (m *Manager) Uninstall(ctx context.Context, purge bool) (Manifest, error) {
	unlock, err := m.lock()
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()
	man, op, err := m.Status()
	if err != nil {
		return man, err
	}
	if op.Stage != "complete" && op.Kind != "install" {
		return man, errors.New("another operation is pending; use recover")
	}
	if man.State == "purged" {
		return man, nil
	}
	op = Operation{Kind: "uninstall", Stage: "prepared", Purge: purge}
	if err = m.saveOperation(op); err != nil {
		return man, err
	}
	return m.uninstall(ctx, man, op)
}

func (m *Manager) uninstall(ctx context.Context, man Manifest, op Operation) (Manifest, error) {
	if err := m.removeUpdateUnits(ctx, man); err != nil {
		return man, err
	}
	if err := m.stop(ctx, man); err != nil {
		return man, err
	}
	disable := []string{"disable"}
	for _, path := range []string{m.Layout.socket(), m.Layout.service()} {
		if _, err := os.Lstat(path); err == nil {
			disable = append(disable, filepath.Base(path))
		}
	}
	if len(disable) > 1 {
		if _, err := m.Runner.Run(ctx, "systemctl", disable...); err != nil {
			return man, err
		}
	}
	if man.Rule != nil {
		if err := RemoveRule(ctx, m.Runner, *man.Rule); err != nil {
			man.State = "cleanup_pending"
			_ = m.save(man)
			return man, err
		}
	}
	for _, p := range []string{m.Layout.service(), m.Layout.socket()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return man, err
		}
	}
	if _, err := m.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return man, err
	}
	if err := os.RemoveAll(m.Layout.app()); err != nil {
		return man, err
	}
	man.State = "removed_data_retained"
	if op.Purge {
		for _, p := range []string{m.Layout.data(), m.Layout.conf(), filepath.Join(m.Layout.meta(), "backups")} {
			if err := os.RemoveAll(p); err != nil {
				return man, err
			}
		}
		// Keep the system account and a small root-owned audit manifest. Removing
		// an account could orphan files or affect later uses of that numeric UID.
		man.State = "purged"
		man.Pin = ""
	}
	if err := m.save(man); err != nil {
		return man, err
	}
	op.Stage = "complete"
	return man, m.saveOperation(op)
}

func (m *Manager) Update(ctx context.Context, bundle string) (Manifest, error) {
	return m.UpdateWithOptions(ctx, UpdateOptions{Bundle: bundle})
}

func (m *Manager) UpdateWithOptions(ctx context.Context, o UpdateOptions) (Manifest, error) {
	unlock, err := m.lock()
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()
	man, err := m.checkIdle()
	if err != nil {
		return man, err
	}
	if o.ExpectedPolicy != nil {
		policy, policyErr := m.UpdatePolicy()
		if policyErr != nil {
			return man, policyErr
		}
		if !policy.Enabled || policy.Channel != o.ExpectedPolicy.Channel || policy.AllowUnsigned != o.ExpectedPolicy.AllowUnsigned {
			return man, errors.New("automatic update policy changed; update cancelled")
		}
	}
	verified, err := release.Inspect(filepath.Join(o.Bundle, "release.json"), man.TrustKey, man.HighestSequence, time.Now(), o.AllowUnsigned)
	if err != nil {
		return man, err
	}
	metadata := verified.Metadata
	if metadata.Channel == "stable" && updates.IsStableDowngrade(metadata.Version, man.Version) {
		return man, errors.New("stable updates cannot downgrade the installed version; use explicit compatible rollback instead")
	}
	if err = release.CheckArtifacts(o.Bundle, metadata); err != nil {
		return man, err
	}
	bundle, err := filepath.Abs(o.Bundle)
	if err != nil {
		return man, err
	}
	var previous *PreviousRelease
	if man.ReleaseMetadata != nil {
		previous = &PreviousRelease{Metadata: *man.ReleaseMetadata, Unsigned: man.Unsigned}
	}
	op := Operation{Kind: "update", Stage: "prepared", Bundle: bundle, Release: metadata, Unsigned: !verified.Signed, Previous: previous, RollbackOnFailure: o.RollbackOnFailure}
	if err = m.saveOperation(op); err != nil {
		return man, err
	}
	return m.update(ctx, man, op)
}

func (m *Manager) update(ctx context.Context, man Manifest, op Operation) (result Manifest, updateErr error) {
	stopped := false
	activated := false
	defer func() {
		if updateErr == nil || !stopped || activated || op.Previous == nil || op.Previous.Metadata.Schema != 2 {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
		defer cancel()
		if verifyErr := release.CheckArtifacts(m.Layout.binaryDir(op.Previous.Metadata.Sequence), op.Previous.Metadata); verifyErr != nil {
			updateErr = errors.Join(updateErr, fmt.Errorf("verify previous executable: %w", verifyErr))
			return
		}
		if restoreErr := m.link(op.Previous.Metadata.Sequence); restoreErr != nil {
			updateErr = errors.Join(updateErr, fmt.Errorf("restore previous executable: %w", restoreErr))
			return
		}
		if restartErr := m.start(cleanup, man); restartErr != nil {
			updateErr = errors.Join(updateErr, fmt.Errorf("restart previous service: %w", restartErr))
		}
	}()
	if op.Release.Sequence <= man.Sequence && op.Stage != "activated" {
		return man, errors.New("update operation is inconsistent")
	}
	if err := m.stage(op.Bundle, op.Release); err != nil {
		return man, err
	}
	stopped = true
	if err := m.stop(ctx, man); err != nil {
		return man, err
	}
	s, err := store.Open(ctx, man.Config.Database, limits(man.Config))
	if err != nil {
		return man, err
	}
	backupDir := filepath.Join(m.Layout.meta(), "backups")
	if err = secureDirectory(backupDir, os.Geteuid(), os.Getegid(), 0700); err != nil {
		_ = s.Close()
		return man, err
	}
	backup := filepath.Join(backupDir, strconv.FormatUint(op.Release.Sequence, 10)+".sqlite")
	if _, err = os.Lstat(backup); errors.Is(err, os.ErrNotExist) {
		err = s.Backup(ctx, backup)
	}
	closeErr := s.Close()
	if err != nil {
		return man, err
	}
	if closeErr != nil {
		return man, closeErr
	}
	// Enrollment schema migration is additive. Keep the live database and its
	// durable revocations. Recovery never copies an old backup over new writes.
	if err = m.link(op.Release.Sequence); err != nil {
		return man, err
	}
	activated = true
	man.Sequence = op.Release.Sequence
	man.HighestSequence = op.Release.Sequence
	man.Version = op.Release.Version
	man.Unsigned = op.Unsigned
	man.ReleaseMetadata = &op.Release
	man.PreviousRelease = op.Previous
	op.Stage = "activated"
	if err = m.saveOperation(op); err != nil {
		return man, err
	}
	if err = m.save(man); err != nil {
		return man, err
	}
	if err = m.start(ctx, man); err != nil {
		if op.RollbackOnFailure && op.Previous != nil && op.Previous.Metadata.Schema == 2 {
			rollback := Operation{Kind: "rollback", Stage: "prepared", Release: op.Previous.Metadata, Unsigned: op.Previous.Unsigned}
			if journalErr := m.saveOperation(rollback); journalErr != nil {
				return man, errors.Join(err, journalErr)
			}
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
			defer cancel()
			restored, rollbackErr := m.rollback(cleanup, man, rollback)
			if rollbackErr != nil {
				return restored, errors.Join(err, fmt.Errorf("rollback failed: %w", rollbackErr))
			}
			return restored, fmt.Errorf("new release failed its health check; previous version restored: %w", err)
		}
		return man, err
	}
	op.Stage = "complete"
	return man, m.saveOperation(op)
}

func (m *Manager) Rollback(ctx context.Context) (Manifest, error) {
	unlock, err := m.lock()
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()
	man, err := m.checkIdle()
	if err != nil {
		return man, err
	}
	if man.PreviousRelease == nil || man.PreviousRelease.Metadata.Schema != 2 {
		return man, errors.New("no retained release compatible with the live database; schema-1 downgrade is prohibited")
	}
	previous := man.PreviousRelease
	op := Operation{Kind: "rollback", Stage: "prepared", Release: previous.Metadata, Unsigned: previous.Unsigned}
	if err = release.CheckArtifacts(m.Layout.binaryDir(op.Release.Sequence), op.Release); err != nil {
		return man, err
	}
	if err = m.saveOperation(op); err != nil {
		return man, err
	}
	return m.rollback(ctx, man, op)
}

func (m *Manager) rollback(ctx context.Context, man Manifest, op Operation) (Manifest, error) {
	if op.Release.Schema != 2 || op.Release.Sequence > man.HighestSequence {
		return man, errors.New("rollback is incompatible with the live database or installation")
	}
	if err := release.CheckArtifacts(m.Layout.binaryDir(op.Release.Sequence), op.Release); err != nil {
		return man, err
	}
	if err := m.stop(ctx, man); err != nil {
		return man, err
	}
	// Restore only executables. Replacing SQLite with an earlier snapshot would
	// discard settings and could resurrect revoked device credentials.
	if err := m.link(op.Release.Sequence); err != nil {
		return man, err
	}
	man.Sequence = op.Release.Sequence
	man.Version = op.Release.Version
	man.Unsigned = op.Unsigned
	man.ReleaseMetadata = &op.Release
	man.PreviousRelease = nil
	if err := m.save(man); err != nil {
		return man, err
	}
	if err := m.start(ctx, man); err != nil {
		return man, err
	}
	op.Stage = "complete"
	return man, m.saveOperation(op)
}
