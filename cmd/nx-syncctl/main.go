package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/fsutil"
	"nx-sync-server/internal/host"
	"nx-sync-server/internal/port"
	"nx-sync-server/internal/probe"
	"nx-sync-server/internal/release"
	"nx-sync-server/internal/store"
	"nx-sync-server/internal/tlsutil"
	"nx-sync-server/internal/updates"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nx-syncctl:", err)
		os.Exit(1)
	}
}

func output(value any) error          { return json.NewEncoder(os.Stdout).Encode(value) }
func flags(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ContinueOnError) }

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("commands: version, init, ping, connection-code, bootstrap, issue-credential, preflight, install, setup, status, update-preflight, update, update-settings, update-status, auto-update, rollback, reset-db, uninstall, recover, release-keygen, sign-release")
	}
	name := args[0]
	args = args[1:]
	switch name {
	case "version":
		return output(map[string]string{"version": config.Version, "target": config.Target()})
	case "init":
		return initialize(ctx, args)
	case "ping":
		f := flags(name)
		endpoint := f.String("endpoint", "", "HTTPS origin")
		pin := f.String("pin", "", "SHA-256 SPKI pin; omitted for normal public CA trust")
		proxy := f.String("proxy", "", "explicit HTTP/HTTPS proxy")
		if err := f.Parse(args); err != nil {
			return err
		}
		r, err := probe.Check(ctx, *endpoint, *pin, *proxy)
		if err != nil {
			return err
		}
		if err = output(r); err != nil {
			return err
		}
		if !r.Ready {
			return errors.New("server is not ready")
		}
		return nil
	case "bootstrap", "issue-credential":
		return credential(ctx, name, args)
	case "connection-code":
		return connectionCode(ctx, args)
	case "release-keygen", "sign-release":
		return publisher(name, args)
	case "status":
		if len(args) != 0 {
			return errors.New("status takes no arguments")
		}
		man, op, err := host.New().Status()
		if err != nil {
			return err
		}
		return output(struct {
			Installation         host.Manifest  `json:"installation"`
			Operation            host.Operation `json:"operation"`
			ExternalReachability string         `json:"external_reachability"`
		}{man, op, "check_from_client"})
	case "update-status":
		if len(args) != 0 {
			return errors.New("update-status takes no arguments")
		}
		policy, err := host.New().UpdatePolicy()
		if err != nil {
			return err
		}
		return output(policy)
	}
	if os.Geteuid() != 0 {
		return errors.New("system administration requires root through a trusted local/SSH session")
	}
	manager := host.New()
	switch name {
	case "update-preflight":
		f := flags(name)
		bundle := f.String("bundle", "", "downloaded release directory")
		channel := f.String("channel", "stable", "stable or dev")
		unsigned := f.Bool("allow-unsigned", false, "acknowledge an unsigned package")
		if err := f.Parse(args); err != nil {
			return err
		}
		installed, operation, err := manager.Status()
		if err != nil {
			return err
		}
		if installed.State != "installed" || operation.Stage != "complete" {
			return errors.New("recover the pending installation operation first")
		}
		verified, err := release.Inspect(filepath.Join(*bundle, "release.json"), installed.TrustKey, 0, time.Now(), *unsigned)
		if err != nil {
			return err
		}
		if verified.Metadata.Channel != *channel {
			return errors.New("package does not match the selected channel")
		}
		if *channel == "stable" && updates.IsStableDowngrade(verified.Metadata.Version, installed.Version) {
			return errors.New("stable release is older than the installed version; use explicit compatible rollback instead")
		}
		if err = release.CheckArtifacts(*bundle, verified.Metadata); err != nil {
			return err
		}
		return output(map[string]any{"version": verified.Metadata.Version, "current_version": installed.Version, "channel": *channel, "unsigned": !verified.Signed, "update_available": verified.Metadata.Sequence > installed.HighestSequence})
	case "install", "preflight", "setup":
		f := flags(name)
		bundle := f.String("bundle", "", "directory containing binaries and release.json")
		trust := f.String("trust-key", "", "trusted Ed25519 public release key, base64")
		unsigned := f.Bool("allow-unsigned", false, "acknowledge unsafe installation of an unsigned package for this operation")
		tlsHost := f.String("tls-host", "", "IP/DNS name clients will use")
		bind := f.String("bind", "0.0.0.0", "listen IP")
		number := f.Int("port", 0, "TCP port; 0 selects a free port in 18443..18543")
		memory := f.Int64("memory-mib", 256, "daemon hard memory budget in MiB")
		block := f.Bool("block-web-ports", true, "prohibit ports 80 and 443")
		zone := f.String("firewall-zone", "", "explicit ingress firewalld zone")
		manual := f.Bool("allow-manual-firewall", false, "administrator explicitly manages unsupported ingress firewall")
		channel := f.String("channel", "", "selected release channel: stable or dev")
		auto := f.Bool("auto-update", false, "enable automatic server updates")
		interval := f.Duration("update-interval", 24*time.Hour, "automatic update check interval (1h to 720h)")
		if err := f.Parse(args); err != nil {
			return err
		}
		verified, err := release.Inspect(filepath.Join(*bundle, "release.json"), *trust, 0, time.Now(), *unsigned)
		if err != nil {
			return err
		}
		if !verified.Signed {
			if _, err := fmt.Fprintln(os.Stderr, release.UnsignedWarning); err != nil {
				return err
			}
		}
		if *channel == "" {
			*channel = verified.Metadata.Channel
		}
		if *channel != verified.Metadata.Channel || *interval < time.Hour || *interval > 30*24*time.Hour {
			return errors.New("invalid selected channel or update interval")
		}
		o := host.InstallOptions{Bundle: *bundle, TrustKey: *trust, TLSHost: *tlsHost, Bind: *bind, Port: *number, MemoryBytes: *memory << 20, BlockWebPorts: *block, FirewallZone: *zone, AllowManualFirewall: *manual, AllowUnsigned: *unsigned}
		if err := host.CheckSystem(o.MemoryBytes); err != nil {
			return err
		}
		if name == "preflight" {
			result, err := manager.Preflight(ctx, o)
			if err != nil {
				return err
			}
			return output(result)
		}
		man, err := manager.Install(ctx, o)
		if err != nil {
			return err
		}
		if _, err = manager.ConfigureUpdates(ctx, host.UpdatePolicy{Enabled: *auto, Channel: *channel, IntervalSeconds: int64(*interval / time.Second), AllowUnsigned: *unsigned}); err != nil {
			return err
		}
		if name == "setup" {
			_, port, splitErr := net.SplitHostPort(man.Config.Listen)
			if splitErr != nil {
				return splitErr
			}
			origin := "https://" + net.JoinHostPort(*tlsHost, port)
			code, expires, codeErr := newConnectionCode(ctx, "/etc/nx-syncd/config.json", origin)
			if codeErr != nil {
				return codeErr
			}
			return output(struct {
				Installation   host.Manifest `json:"installation"`
				ConnectionCode string        `json:"connection_code"`
				Expires        int64         `json:"expires_at"`
			}{man, code, expires})
		}
		return output(man)
	case "update":
		f := flags(name)
		bundle := f.String("bundle", "", "directory containing a newer release")
		unsigned := f.Bool("allow-unsigned", false, "acknowledge unsafe installation of an unsigned update for this operation")
		channel := f.String("channel", "", "GitHub release channel; stable is the default when --bundle is omitted")
		rollback := f.Bool("rollback-on-failure", true, "restore compatible previous executables if the new daemon fails health checks")
		ifNewer := f.Bool("if-newer", false, "succeed without changes when the downloaded release is already installed or older")
		if err := f.Parse(args); err != nil {
			return err
		}
		if *bundle == "" {
			if *channel == "" {
				*channel = "stable"
			}
			if *unsigned {
				if _, err := fmt.Fprintln(os.Stderr, release.UnsignedWarning); err != nil {
					return err
				}
			}
			result, err := manager.UpdateOnline(ctx, *channel, *unsigned)
			if err != nil {
				return err
			}
			return output(result)
		}
		installed, _, err := manager.Status()
		if err != nil {
			return err
		}
		minimum := installed.HighestSequence
		if *ifNewer {
			minimum = 0
		}
		verified, err := release.Inspect(filepath.Join(*bundle, "release.json"), installed.TrustKey, minimum, time.Now(), *unsigned)
		if err != nil {
			return err
		}
		if *channel != "" && *channel != verified.Metadata.Channel {
			return errors.New("downloaded package does not match the selected channel")
		}
		if *ifNewer && verified.Metadata.Sequence <= installed.HighestSequence {
			if err = release.CheckArtifacts(*bundle, verified.Metadata); err != nil {
				return err
			}
			return output(map[string]any{"updated": false, "installation": installed})
		}
		if !verified.Signed {
			if _, err := fmt.Fprintln(os.Stderr, release.UnsignedWarning); err != nil {
				return err
			}
		}
		man, err := manager.UpdateWithOptions(ctx, host.UpdateOptions{Bundle: *bundle, AllowUnsigned: *unsigned, RollbackOnFailure: *rollback})
		if err != nil {
			return err
		}
		return output(man)
	case "update-settings":
		f := flags(name)
		enabled := f.Bool("enabled", false, "enable automatic update checks")
		channel := f.String("channel", "stable", "stable or dev; dev is never chosen implicitly")
		interval := f.Duration("interval", 24*time.Hour, "check interval: 1h to 720h")
		unsigned := f.Bool("allow-unsigned", false, "authorize future unsigned updates from this repository for this configured policy")
		if err := f.Parse(args); err != nil {
			return err
		}
		if *unsigned {
			if _, err := fmt.Fprintln(os.Stderr, release.UnsignedWarning+" This policy also authorizes unattended unsigned updates while enabled."); err != nil {
				return err
			}
		}
		policy, err := manager.ConfigureUpdates(ctx, host.UpdatePolicy{Enabled: *enabled, Channel: *channel, IntervalSeconds: int64(*interval / time.Second), AllowUnsigned: *unsigned})
		if err != nil {
			return err
		}
		return output(policy)
	case "auto-update":
		if len(args) != 0 {
			return errors.New("auto-update takes no arguments")
		}
		result, err := manager.AutoUpdate(ctx)
		if err != nil {
			return err
		}
		return output(result)
	case "rollback":
		if len(args) != 0 {
			return errors.New("rollback takes no arguments")
		}
		man, err := manager.Rollback(ctx)
		if err != nil {
			return err
		}
		return output(man)
	case "reset-db":
		f := flags(name)
		confirm := f.Bool("confirm-reset", false, "explicitly remove all profiles and invalidate all device credentials")
		if err := f.Parse(args); err != nil {
			return err
		}
		if !*confirm {
			return errors.New("reset-db requires --confirm-reset")
		}
		man, err := manager.Reset(ctx)
		if err != nil {
			return err
		}
		return output(man)
	case "uninstall":
		f := flags(name)
		purge := f.Bool("purge-data", false, "remove the database, TLS identity, config and own backups")
		if err := f.Parse(args); err != nil {
			return err
		}
		man, err := manager.Uninstall(ctx, *purge)
		if err != nil {
			return err
		}
		return output(man)
	case "recover":
		if len(args) != 0 {
			return errors.New("recover takes no arguments")
		}
		man, err := manager.Recover(ctx)
		if err != nil {
			return err
		}
		return output(man)
	default:
		return errors.New("unknown command")
	}
}

func initialize(ctx context.Context, args []string) error {
	f := flags("init")
	dir := f.String("dir", "", "new directory for local data and configuration")
	tlsHost := f.String("tls-host", "127.0.0.1", "certificate IP/DNS name")
	bind := f.String("bind", "127.0.0.1", "listen IP")
	number := f.Int("port", 18443, "TCP port; 0 selects a free port")
	block := f.Bool("block-web-ports", true, "prohibit ports 80/443")
	memory := f.Int64("memory-mib", 256, "Go runtime memory budget in MiB")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("--dir required")
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	l, err := port.Reserve(ctx, port.Policy{Host: *bind, Port: *number, BlockWebPorts: *block})
	if err != nil {
		return err
	}
	defer l.Close()
	c := config.Defaults()
	c.Listen = l.Addr().String()
	c.Database = filepath.Join(abs, "settings.sqlite")
	c.TLSKey = filepath.Join(abs, "server.key")
	c.TLSCertificate = filepath.Join(abs, "server.pem")
	c.TLSHost = *tlsHost
	c.MemoryBytes = *memory << 20
	c.BlockWebPorts = *block
	if err = c.Validate(); err != nil {
		return err
	}
	if err = os.Mkdir(abs, 0700); err != nil {
		return err
	}
	s, err := store.Create(ctx, c.Database, store.Limits{EnvelopeBytes: c.MaxEnvelopeBytes, ProfileBytes: c.MaxProfileBytes, Devices: c.MaxDevices})
	if err != nil {
		return err
	}
	id, err := s.Identity(ctx)
	closeErr := s.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	pin, err := tlsutil.Create(c.TLSKey, c.TLSCertificate, c.TLSHost, time.Now())
	if err != nil {
		return err
	}
	path := filepath.Join(abs, "config.json")
	if err = fsutil.WriteJSON(path, c, 0600); err != nil {
		return err
	}
	return output(map[string]any{"config": path, "listen": c.Listen, "tls_host": c.TLSHost, "pin": pin, "store": id})
}

func exclusive(path string, data []byte) error {
	if path == "" {
		return errors.New("output file required")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func credential(ctx context.Context, name string, args []string) error {
	f := flags(name)
	path := f.String("config", "/etc/nx-syncd/config.json", "local configuration")
	deviceKey := f.String("device-key", "", "client Ed25519 public writer key, base64")
	ownerKey := f.String("owner-key", "", "client Ed25519 public owner authority key, base64")
	profile := f.String("profile", "", "profile ID")
	device := f.String("device", "", "active signed member ID")
	out := f.String("out", "", "new private credential file; tokens are never printed")
	if err := f.Parse(args); err != nil {
		return err
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	// Reserve the output before changing the database: an existing private file
	// must never be overwritten, and a failed output must not rotate a token.
	if err = exclusive(*out, nil); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(*out)
		}
	}()
	s, err := store.Open(ctx, c.Database, store.Limits{EnvelopeBytes: c.MaxEnvelopeBytes, ProfileBytes: c.MaxProfileBytes, Devices: c.MaxDevices})
	if err != nil {
		return err
	}
	defer s.Close()
	var result store.Credential
	if name == "bootstrap" {
		dk, err := base64.StdEncoding.DecodeString(*deviceKey)
		if err != nil {
			return errors.New("invalid device public key")
		}
		ok, err := base64.StdEncoding.DecodeString(*ownerKey)
		if err != nil {
			return errors.New("invalid owner public key")
		}
		result, err = s.Bootstrap(ctx, dk, ok)
		if err != nil {
			return err
		}
	} else {
		result, err = s.IssueCredential(ctx, *profile, *device)
		if err != nil {
			return err
		}
	}
	if err = fsutil.WriteJSON(*out, result, 0600); err != nil {
		return err
	}
	complete = true
	return output(map[string]string{"credential_file": *out, "profile_id": result.ProfileID, "device_id": result.DeviceID, "generation": result.Generation})
}

func publisher(name string, args []string) error {
	f := flags(name)
	if name == "release-keygen" {
		out := f.String("out", "", "new private release-key file (keep offline)")
		if err := f.Parse(args); err != nil {
			return err
		}
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if err = exclusive(*out, []byte(base64.StdEncoding.EncodeToString(key)+"\n")); err != nil {
			return err
		}
		return output(map[string]string{"trust_key": base64.StdEncoding.EncodeToString(pub), "private_key_file": *out})
	}
	bundle := f.String("bundle", "", "artifact directory")
	keyPath := f.String("private-key-file", "", "offline private publisher key")
	version := f.String("version", "", "stable version X.Y.Z")
	target := f.String("target", config.Target(), "exact target from packaging/targets.txt")
	sequence := f.Uint64("sequence", 0, "strictly increasing release number")
	expires := f.String("expires", "", "RFC3339 expiration, at most 90 days")
	if err := f.Parse(args); err != nil {
		return err
	}
	info, err := os.Lstat(*keyPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("publisher key must be a private regular file")
	}
	file, err := os.OpenFile(*keyPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	data, err := fsutil.ReadBounded(file, 1024)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid private release key")
	}
	when, err := time.Parse(time.RFC3339, *expires)
	if err != nil {
		return err
	}
	if err = release.Sign(*bundle, *version, *target, *sequence, when, ed25519.PrivateKey(key)); err != nil {
		return err
	}
	return output(map[string]string{"release": filepath.Join(*bundle, "release.json"), "target": *target})
}
