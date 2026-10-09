package host

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/port"
	"nx-sync-server/internal/release"
)

// installationTarget permits reuse only after a completed owned uninstall.
// Preflight also calls it, so ownership checks here must remain read-only.
func (m *Manager) installationTarget(ctx context.Context, o InstallOptions) (*Manifest, InstallOptions, error) {
	if o.Bind == "" {
		o.Bind = "0.0.0.0"
	}
	if o.MemoryBytes == 0 {
		o.MemoryBytes = 256 << 20
	}
	if _, err := os.Lstat(m.Layout.manifest()); errors.Is(err, os.ErrNotExist) {
		return nil, o, m.checkFresh(ctx)
	} else if err != nil {
		return nil, o, err
	}
	man, op, err := m.Status()
	if err != nil {
		return nil, o, err
	}
	retained := man.State == "removed_data_retained"
	if (!retained && man.State != "purged") || op.Kind != "uninstall" || op.Stage != "complete" {
		return nil, o, errors.New("installation metadata exists; use status or recover")
	}
	if err := m.checkRemoved(ctx, man); err != nil {
		return nil, o, err
	}
	if o.TrustKey != "" && o.TrustKey != man.TrustKey {
		return nil, o, errors.New("reinstallation cannot change the pinned release publisher")
	}
	o.TrustKey = man.TrustKey
	if retained {
		bind, text, err := net.SplitHostPort(man.Config.Listen)
		if err != nil {
			return nil, o, err
		}
		number, err := strconv.Atoi(text)
		if err != nil {
			return nil, o, err
		}
		if o.Bind != bind || o.Port != 0 && o.Port != number || o.TLSHost != man.Config.TLSHost || o.MemoryBytes != man.Config.MemoryBytes || o.BlockWebPorts != man.Config.BlockWebPorts {
			return nil, o, errors.New("retained reinstallation must preserve the bind, port, TLS name and daemon policy")
		}
		o.Port = number
	}
	return &man, o, nil
}

// checkRemoved rejects foreign replacements without changing host ownership.
func (m *Manager) checkRemoved(ctx context.Context, man Manifest) error {
	retained := man.State == "removed_data_retained"
	for _, path := range []string{m.Layout.app(), m.Layout.service(), m.Layout.socket(), m.updateServicePath(), m.updateTimerPath(), m.Layout.service() + ".d", m.Layout.socket() + ".d", m.updateServicePath() + ".d", m.updateTimerPath() + ".d"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("removed installation path was recreated or cannot be inspected")
		}
	}
	for _, unit := range []string{"nx-syncd.service", "nx-syncd.socket", "nx-sync-update.service", "nx-sync-update.timer"} {
		output, err := m.Runner.Run(ctx, "systemctl", "show", unit, "--property=LoadState", "--value")
		if err != nil && status(err) != 4 {
			return err
		}
		if value := strings.TrimSpace(string(output)); value != "not-found" && value != "" {
			return errors.New("a foreign unit uses the removed installation name")
		}
	}
	for name, path := range map[string]string{"config": m.Layout.conf(), "data": m.Layout.data()} {
		_, err := os.Lstat(path)
		if retained {
			if err != nil || man.DirectoryIDs[name] == "" {
				return errors.New("retained installation directory is missing or unrecorded")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("purged installation path was recreated or cannot be inspected")
		}
	}
	if err := m.directories(&man, false); err != nil {
		return err
	}
	output, err := m.Runner.Run(ctx, "getent", "passwd", "nx-syncd")
	if err != nil {
		return errors.New("recorded service account disappeared or cannot be inspected")
	}
	fields := strings.Split(strings.TrimSpace(string(output)), ":")
	if len(fields) != 7 || fields[0] != "nx-syncd" || man.UID <= 0 || man.GID <= 0 {
		return errors.New("invalid recorded service account")
	}
	uid, uidErr := strconv.Atoi(fields[2])
	gid, gidErr := strconv.Atoi(fields[3])
	if uidErr != nil || gidErr != nil || uid != man.UID || gid != man.GID {
		return errors.New("service account identity changed")
	}
	return nil
}

// inspectReinstallation permits the exact current release or a newer release.
// Older sequences and replacements at an accepted sequence remain forbidden.
func inspectReinstallation(man Manifest, o InstallOptions) (release.Verification, error) {
	verified, err := release.Inspect(filepath.Join(o.Bundle, "release.json"), man.TrustKey, 0, time.Now(), o.AllowUnsigned)
	if err != nil {
		return verified, err
	}
	metadata := verified.Metadata
	if metadata.Sequence < man.HighestSequence || metadata.Sequence == man.HighestSequence && (man.ReleaseMetadata == nil || metadata.Sequence != man.Sequence || !reflect.DeepEqual(metadata, *man.ReleaseMetadata) || !verified.Signed != man.Unsigned) {
		return verified, errors.New("reinstallation cannot replay or replace a previously accepted release")
	}
	return verified, release.CheckArtifacts(o.Bundle, metadata)
}

func (m *Manager) reinstall(ctx context.Context, man Manifest, o InstallOptions) (Manifest, error) {
	verified, err := inspectReinstallation(man, o)
	if err != nil {
		return man, err
	}
	provider, err := DetectFirewall(ctx, m.Runner)
	if err != nil {
		return man, err
	}
	if provider == "manual" && !man.AllowManualFirewall && !o.AllowManualFirewall {
		return man, errors.New("unsupported firewall: explicit manual ingress acknowledgement required before reinstallation")
	}
	if man.State == "purged" {
		listener, err := port.Reserve(ctx, port.Policy{Host: o.Bind, Port: o.Port, BlockWebPorts: o.BlockWebPorts})
		if err != nil {
			return man, err
		}
		c := config.Defaults()
		c.Listen = listener.Addr().String()
		_ = listener.Close()
		c.TLSHost, c.MemoryBytes, c.BlockWebPorts = o.TLSHost, o.MemoryBytes, o.BlockWebPorts
		c.Database, c.TLSKey, c.TLSCertificate = man.Config.Database, man.Config.TLSKey, man.Config.TLSCertificate
		if err := c.Validate(); err != nil {
			return man, err
		}
		man.Config, man.Pin, man.AutoPort = c, "", o.Port == 0
		delete(man.DirectoryIDs, "config")
		delete(man.DirectoryIDs, "data")
	}
	// These paths were checked absent above. Preserve identities of retained
	// directories, the system account, publisher pin and anti-rollback history.
	delete(man.DirectoryIDs, "app")
	man.Rule, man.PreviousRelease = nil, nil
	man.ServiceHash, man.SocketHash = "", ""
	man.PreviousServiceHash, man.PreviousSocketHash = "", ""
	man.State = "installing"
	metadata := verified.Metadata
	man.Sequence, man.Version, man.Unsigned, man.ReleaseMetadata = metadata.Sequence, metadata.Version, !verified.Signed, &metadata
	if metadata.Sequence > man.HighestSequence {
		man.HighestSequence = metadata.Sequence
	}
	man.AllowManualFirewall = man.AllowManualFirewall || o.AllowManualFirewall
	if o.FirewallZone != "" {
		man.FirewallZone = o.FirewallZone
	}
	bundle, err := filepath.Abs(o.Bundle)
	if err != nil {
		return man, err
	}
	// Journal the replacement first: recovery can complete the transition if
	// power is lost before the new manifest replaces the removed one.
	op := Operation{Kind: "install", Stage: "prepared", Bundle: bundle, Release: metadata, Unsigned: !verified.Signed, Reinstallation: &man}
	if err := m.saveOperation(op); err != nil {
		return man, err
	}
	if err := m.save(man); err != nil {
		return man, err
	}
	return m.install(ctx, man, op)
}
