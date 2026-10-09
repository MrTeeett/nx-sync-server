package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/fsutil"
	"nx-sync-server/internal/probe"
	"nx-sync-server/internal/release"
	"nx-sync-server/internal/store"
)

type machine struct {
	layout        Layout
	account       bool
	calls         []string
	socket        net.Listener
	failStartOnce bool
}

func unsignedManifest(t *testing.T, bundle string) {
	t.Helper()
	path := filepath.Join(bundle, "release.json")
	var manifest release.Signed
	if err := fsutil.ReadJSON(path, &manifest, 64<<10); err != nil {
		t.Fatal(err)
	}
	manifest.Signature = nil
	if err := fsutil.WriteJSON(path, manifest, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestUnsignedInstallAndUpdateRequireSeparateAcknowledgements(t *testing.T) {
	m, fake, bundle, key, _ := management(t)
	unsignedManifest(t, bundle)
	ctx := context.Background()
	options := InstallOptions{Bundle: bundle, TLSHost: "127.0.0.1", Bind: "127.0.0.1", BlockWebPorts: true}
	if _, err := m.Preflight(ctx, options); err == nil {
		t.Fatal("unsigned preflight accepted without warning acknowledgement")
	}
	if _, err := m.Install(ctx, options); err == nil {
		t.Fatal("unsigned installation accepted without warning acknowledgement")
	}
	if _, err := os.Lstat(m.Layout.service()); !errors.Is(err, os.ErrNotExist) || fake.account {
		t.Fatal("rejected installation created a service or account")
	}
	options.AllowUnsigned = true
	preview, err := m.Preflight(ctx, options)
	if err != nil || !preview.Unsigned {
		t.Fatalf("unsigned preflight: %+v, %v", preview, err)
	}
	man, err := m.Install(ctx, options)
	if err != nil || !man.Unsigned || man.TrustKey != "" || man.State != "installed" {
		t.Fatalf("unsigned install without a key: %+v, %v", man, err)
	}
	if err := release.Sign(bundle, "0.1.1", config.Target(), 2, time.Now().Add(time.Hour), key); err != nil {
		t.Fatal(err)
	}
	unsignedManifest(t, bundle)
	before := len(fake.calls)
	if _, err := m.Update(ctx, bundle); err == nil {
		t.Fatal("unsigned installation silently authorized a later unsigned update")
	}
	if len(fake.calls) != before {
		t.Fatal("unacknowledged update stopped or changed the installed service")
	}
	man, err = m.UpdateWithOptions(ctx, UpdateOptions{Bundle: bundle, AllowUnsigned: true})
	if err != nil || !man.Unsigned || man.Sequence != 2 {
		t.Fatalf("explicit unsigned update: %+v, %v", man, err)
	}
	stored, _, err := m.Status()
	if err != nil || !stored.Unsigned || stored.TrustKey != "" {
		t.Fatalf("unsigned installation status was not retained: %+v, %v", stored, err)
	}
}

func TestUnsignedUpdateRetainsOriginalPublisherPin(t *testing.T) {
	m, _, initial, key := installed(t)
	bundle := t.TempDir()
	for _, name := range []string{"nx-syncd", "nx-syncctl"} {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte("new synthetic binary"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := release.Sign(bundle, "0.1.1", config.Target(), 2, time.Now().Add(time.Hour), key); err != nil {
		t.Fatal(err)
	}
	unsignedManifest(t, bundle)
	man, err := m.UpdateWithOptions(context.Background(), UpdateOptions{Bundle: bundle, AllowUnsigned: true})
	if err != nil || !man.Unsigned || man.TrustKey != initial.TrustKey {
		t.Fatalf("unsigned update changed pinned publisher: %+v, %v", man, err)
	}
	if err := release.Sign(bundle, "0.1.2", config.Target(), 3, time.Now().Add(time.Hour), key); err != nil {
		t.Fatal(err)
	}
	man, err = m.Update(context.Background(), bundle)
	if err != nil || man.Unsigned || man.TrustKey != initial.TrustKey {
		t.Fatalf("return to publisher-verified updates failed: %+v, %v", man, err)
	}
}

func (f *machine) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	switch name {
	case "getent":
		if !f.account {
			return nil, &StatusError{Code: 2}
		}
		uid, gid := os.Geteuid(), os.Getegid()
		if uid == 0 {
			uid = 65534
		}
		if gid == 0 {
			gid = 65534
		}
		return []byte("nx-syncd:x:" + itoa(uid) + ":" + itoa(gid) + ":service:/nonexistent:/usr/sbin/nologin\n"), nil
	case "useradd":
		f.account = true
		return nil, nil
	case "firewall-cmd", "ufw":
		return nil, &StatusError{Code: 127}
	case "nft", "iptables":
		return nil, nil
	case "systemctl":
		if args[0] == "show" {
			return []byte("not-found\n"), nil
		}
		if args[0] == "stop" {
			if f.socket != nil {
				_ = f.socket.Close()
				f.socket = nil
			}
			return nil, nil
		}
		if args[0] == "start" {
			if f.failStartOnce {
				f.failStartOnce = false
				return nil, &StatusError{Code: 1}
			}
			if f.socket == nil {
				data, err := os.ReadFile(f.layout.socket())
				if err != nil {
					return nil, err
				}
				var address string
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(line, "ListenStream=") {
						address = strings.TrimPrefix(line, "ListenStream=")
					}
				}
				f.socket, err = net.Listen("tcp", address)
				if err != nil {
					return nil, err
				}
			}
		}
		return nil, nil
	default:
		return nil, errors.New("unexpected real-machine operation in test")
	}
}

func itoa(value int) string { return fmt.Sprintf("%d", value) }

func management(t *testing.T) (*Manager, *machine, string, ed25519.PrivateKey, string) {
	t.Helper()
	layout := Layout{Root: t.TempDir()}
	fake := &machine{layout: layout}
	t.Cleanup(func() {
		if fake.socket != nil {
			_ = fake.socket.Close()
		}
	})
	m := &Manager{Layout: layout, Runner: fake, Probe: func(context.Context, string, string, string) (probe.Result, error) {
		return probe.Result{Ready: true, ProtocolVersion: 1}, nil
	}}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := t.TempDir()
	for _, name := range []string{"nx-syncd", "nx-syncctl"} {
		if err = os.WriteFile(filepath.Join(bundle, name), []byte("synthetic binary for isolated OS-adapter test"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err = release.Sign(bundle, "0.1.0", config.Target(), 1, time.Now().Add(24*time.Hour), key); err != nil {
		t.Fatal(err)
	}
	return m, fake, bundle, key, base64.StdEncoding.EncodeToString(pub)
}

func installed(t *testing.T) (*Manager, *machine, Manifest, ed25519.PrivateKey) {
	t.Helper()
	m, fake, bundle, key, trust := management(t)
	man, err := m.Install(context.Background(), InstallOptions{Bundle: bundle, TrustKey: trust, TLSHost: "127.0.0.1", Bind: "127.0.0.1", BlockWebPorts: true})
	if err != nil {
		t.Fatal(err)
	}
	if man.State != "installed" || fake.socket == nil {
		t.Fatalf("not installed: %+v", man)
	}
	return m, fake, man, key
}

func TestInstallUpdateResetAndRetainedData(t *testing.T) {
	m, fake, man, key := installed(t)
	ctx := context.Background()
	foreign := filepath.Join(m.Layout.Root, "etc", "nginx", "nginx.conf")
	if err := os.MkdirAll(filepath.Dir(foreign), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("foreign nginx config"), 0644); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(ctx, man.Config.Database, limits(man.Config))
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Identity(ctx)
	_ = s.Close()
	if err != nil {
		t.Fatal(err)
	}
	bundle := t.TempDir()
	for _, name := range []string{"nx-syncd", "nx-syncctl"} {
		if err = os.WriteFile(filepath.Join(bundle, name), []byte("next synthetic binary"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err = release.Sign(bundle, "0.1.1", config.Target(), 2, time.Now().Add(24*time.Hour), key); err != nil {
		t.Fatal(err)
	}
	man, err = m.Update(ctx, bundle)
	if err != nil || man.Sequence != 2 {
		t.Fatalf("update: %+v %v", man, err)
	}
	if _, err = m.Update(ctx, bundle); err == nil {
		t.Fatal("same release replay accepted")
	}
	s, err = store.Open(ctx, man.Config.Database, limits(man.Config))
	if err != nil {
		t.Fatal(err)
	}
	after, err := s.Identity(ctx)
	_ = s.Close()
	if err != nil || before != after {
		t.Fatalf("update changed identity: %+v %+v %v", before, after, err)
	}
	man, err = m.Reset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s, err = store.Open(ctx, man.Config.Database, limits(man.Config))
	if err != nil {
		t.Fatal(err)
	}
	reset, err := s.Identity(ctx)
	_ = s.Close()
	if err != nil || reset.Generation == before.Generation || reset.StoreID != before.StoreID {
		t.Fatalf("reset identity: %+v %v", reset, err)
	}
	man, err = m.Uninstall(ctx, false)
	if err != nil || man.State != "removed_data_retained" {
		t.Fatalf("uninstall: %+v %v", man, err)
	}
	if _, err = os.Stat(man.Config.Database); err != nil {
		t.Fatal("database was removed without explicit purge")
	}
	if _, err = os.Lstat(m.Layout.app()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("executables retained: %v", err)
	}
	man, err = m.Uninstall(ctx, true)
	if err != nil || man.State != "purged" {
		t.Fatalf("purge: %+v %v", man, err)
	}
	if _, err = os.Stat(man.Config.Database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("database not purged: %v", err)
	}
	data, err := os.ReadFile(foreign)
	if err != nil || string(data) != "foreign nginx config" {
		t.Fatal("foreign service was changed")
	}
	for _, call := range fake.calls {
		if strings.Contains(call, "nginx") || strings.Contains(call, "firewall-cmd --reload") || strings.Contains(call, "ufw reset") {
			t.Fatalf("foreign/global mutation: %s", call)
		}
	}
}

func TestInterruptedInstallRecoversWithoutSourceBundle(t *testing.T) {
	m, fake, bundle, _, trust := management(t)
	fake.failStartOnce = true
	if _, err := m.Install(context.Background(), InstallOptions{Bundle: bundle, TrustKey: trust, TLSHost: "127.0.0.1", Bind: "127.0.0.1", BlockWebPorts: true}); err == nil {
		t.Fatal("injected failure was ignored")
	}
	if err := os.RemoveAll(bundle); err != nil {
		t.Fatal(err)
	}
	man, err := m.Recover(context.Background())
	if err != nil || man.State != "installed" {
		t.Fatalf("recover: %+v %v", man, err)
	}
	_, op, err := m.Status()
	if err != nil || op.Stage != "complete" {
		t.Fatalf("journal=%+v err=%v", op, err)
	}
}

func TestForeignUnitAndUntrustedUpdateAreNotChanged(t *testing.T) {
	m, fake, man, _ := installed(t)
	ctx := context.Background()
	if err := os.WriteFile(m.Layout.service(), []byte("foreign replaced unit"), 0644); err != nil {
		t.Fatal(err)
	}
	calls := len(fake.calls)
	if _, err := m.Uninstall(ctx, false); err == nil {
		t.Fatal("foreign unit overwritten")
	}
	if len(fake.calls) != calls {
		t.Fatal("system commands executed after ownership failed")
	}
	if _, err := os.Stat(man.Config.Database); err != nil {
		t.Fatal("foreign unit failure deleted database")
	}
}

func TestLifecycleLockAndSymlinkRefusal(t *testing.T) {
	m, _, _, _, _ := management(t)
	unlock, err := m.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if second, err := m.lock(); err == nil {
		second()
		t.Fatal("concurrent root operation acquired the lock")
	}
	path := filepath.Join(t.TempDir(), "redirect")
	if err = os.Symlink(t.TempDir(), path); err != nil {
		t.Fatal(err)
	}
	if secureDirectory(filepath.Join(path, "child"), os.Geteuid(), os.Getegid(), 0700) == nil {
		t.Fatal("followed an installation directory symlink")
	}
}
