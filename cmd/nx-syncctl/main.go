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
		return errors.New("commands: version, init, ping, bootstrap, issue-credential, preflight, install, status, update, reset-db, uninstall, recover, release-keygen, sign-release")
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
	}
	if os.Geteuid() != 0 {
		return errors.New("system administration requires root through a trusted local/SSH session")
	}
	manager := host.New()
	switch name {
	case "install", "preflight":
		f := flags(name)
		bundle := f.String("bundle", "", "directory containing binaries and signed release.json")
		trust := f.String("trust-key", "", "trusted Ed25519 public release key, base64")
		tlsHost := f.String("tls-host", "", "IP/DNS name clients will use")
		bind := f.String("bind", "0.0.0.0", "listen IP")
		number := f.Int("port", 0, "TCP port; 0 selects a free port in 18443..18543")
		memory := f.Int64("memory-mib", 256, "daemon hard memory budget in MiB")
		block := f.Bool("block-web-ports", true, "prohibit ports 80 and 443")
		zone := f.String("firewall-zone", "", "explicit ingress firewalld zone")
		manual := f.Bool("allow-manual-firewall", false, "administrator explicitly manages unsupported ingress firewall")
		if err := f.Parse(args); err != nil {
			return err
		}
		o := host.InstallOptions{Bundle: *bundle, TrustKey: *trust, TLSHost: *tlsHost, Bind: *bind, Port: *number, MemoryBytes: *memory << 20, BlockWebPorts: *block, FirewallZone: *zone, AllowManualFirewall: *manual}
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
		return output(man)
	case "update":
		f := flags(name)
		bundle := f.String("bundle", "", "directory containing a newer signed release")
		if err := f.Parse(args); err != nil {
			return err
		}
		man, err := manager.Update(ctx, *bundle)
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
