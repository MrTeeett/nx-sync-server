package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/release"
	"nx-sync-server/internal/store"
)

func TestReinstallPreservesRetainedDataAndRecreatesPurgedIdentity(t *testing.T) {
	for _, purge := range []bool{false, true} {
		name := "retained"
		if purge {
			name = "purged"
		}
		t.Run(name, func(t *testing.T) {
			m, fake, bundle, _, trust := management(t)
			ctx := context.Background()
			o := InstallOptions{Bundle: bundle, TrustKey: trust, TLSHost: "127.0.0.1", Bind: "127.0.0.1", BlockWebPorts: true}
			before, err := m.Install(ctx, o)
			if err != nil {
				t.Fatal(err)
			}
			s, err := store.Open(ctx, before.Config.Database, limits(before.Config))
			if err != nil {
				t.Fatal(err)
			}
			identity, err := s.Identity(ctx)
			if err != nil {
				t.Fatal(err)
			}
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := s.Bootstrap(ctx, pub, pub)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			removed, err := m.Uninstall(ctx, purge)
			if err != nil {
				t.Fatal(err)
			}
			calls := len(fake.calls)
			preview, err := m.Preflight(ctx, o)
			if err != nil || preview.RetainedData == purge {
				t.Fatalf("reinstall preview: %+v %v", preview, err)
			}
			stored, op, err := m.Status()
			if err != nil || stored.State != removed.State || op.Stage != "complete" || fake.socket != nil {
				t.Fatalf("preflight changed installation: %s %s %v", stored.State, op.Stage, err)
			}
			for _, call := range fake.calls[calls:] {
				if strings.HasPrefix(call, "useradd ") || strings.HasPrefix(call, "systemctl start ") || strings.HasPrefix(call, "systemctl stop ") {
					t.Fatalf("preflight mutated host: %s", call)
				}
			}
			after, err := m.Install(ctx, o)
			if err != nil || after.State != "installed" || fake.socket == nil {
				t.Fatalf("reinstall: %s %v", after.State, err)
			}
			if after.InstallationID != before.InstallationID || after.TrustKey != before.TrustKey || after.HighestSequence != before.HighestSequence || after.UID != before.UID || after.GID != before.GID {
				t.Fatal("reinstallation changed ownership or release trust history")
			}
			s, err = store.Open(ctx, after.Config.Database, limits(after.Config))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			current, err := s.Identity(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, authErr := s.State(ctx, credential.ProfileID, credential.Generation, credential.Token)
			if purge {
				if current.StoreID == identity.StoreID || current.Generation == identity.Generation || after.Pin == before.Pin || authErr == nil {
					t.Fatal("purged reinstallation reused the old TLS/database/device identity")
				}
			} else if current != identity || after.Pin != before.Pin || after.Config != before.Config || authErr != nil {
				t.Fatalf("retained reinstallation changed data, port or TLS: %v", authErr)
			}
		})
	}
}

func TestReinstallRefusesForeignPathsAccountPendingOperationAndReleaseReplacement(t *testing.T) {
	for _, name := range []string{"app", "directory", "symlink", "unit", "dropin", "account", "pending", "publisher", "same_sequence", "replay", "unsigned"} {
		t.Run(name, func(t *testing.T) {
			m, fake, bundle, key, trust := management(t)
			ctx := context.Background()
			o := InstallOptions{Bundle: bundle, TrustKey: trust, TLSHost: "127.0.0.1", Bind: "127.0.0.1", BlockWebPorts: true}
			if _, err := m.Install(ctx, o); err != nil {
				t.Fatal(err)
			}
			removed, err := m.Uninstall(ctx, false)
			if err != nil {
				t.Fatal(err)
			}
			var mutationErr error
			switch name {
			case "app":
				mutationErr = os.Mkdir(m.Layout.app(), 0755)
			case "directory", "symlink":
				if err := os.Rename(m.Layout.data(), m.Layout.data()+".original"); err != nil {
					t.Fatal(err)
				}
				if name == "symlink" {
					mutationErr = os.Symlink(m.Layout.data()+".original", m.Layout.data())
				} else {
					mutationErr = os.Mkdir(m.Layout.data(), 0750)
				}
			case "unit":
				mutationErr = os.WriteFile(m.Layout.service(), []byte("foreign unit"), 0644)
			case "dropin":
				mutationErr = os.Mkdir(m.Layout.service()+".d", 0755)
			case "account":
				fake.account = false
			case "pending":
				mutationErr = m.saveOperation(Operation{Kind: "uninstall", Stage: "prepared"})
			case "publisher":
				o.TrustKey = "different publisher"
			case "same_sequence":
				mutationErr = release.Sign(bundle, "0.1.1", config.Target(), 1, time.Now().Add(time.Hour), key)
			case "replay":
				removed.HighestSequence = 2
				mutationErr = m.save(removed)
			case "unsigned":
				unsignedManifest(t, bundle)
				o.AllowUnsigned = true
			}
			if mutationErr != nil {
				t.Fatal(mutationErr)
			}
			calls := len(fake.calls)
			if _, err := m.Preflight(ctx, o); err == nil {
				t.Fatal("unsafe reinstallation passed preflight")
			}
			if _, err := m.Install(ctx, o); err == nil {
				t.Fatal("unsafe reinstallation succeeded")
			}
			stored, _, err := m.Status()
			if err != nil || stored.State != removed.State || fake.socket != nil {
				t.Fatalf("rejected reinstallation mutated state: %s %v", stored.State, err)
			}
			for _, call := range fake.calls[calls:] {
				if strings.HasPrefix(call, "useradd ") || strings.HasPrefix(call, "systemctl start ") || strings.HasPrefix(call, "systemctl stop ") {
					t.Fatalf("rejected reinstallation mutated host: %s", call)
				}
			}
			if name == "unit" {
				data, err := os.ReadFile(m.Layout.service())
				if err != nil || string(data) != "foreign unit" {
					t.Fatal("foreign unit was changed")
				}
			}
		})
	}
}

func TestReinstallRecoveryAfterJournalBeforeManifest(t *testing.T) {
	m, fake, bundle, _, trust := management(t)
	ctx := context.Background()
	if _, err := m.Install(ctx, InstallOptions{Bundle: bundle, TrustKey: trust, TLSHost: "127.0.0.1", Bind: "127.0.0.1", BlockWebPorts: true}); err != nil {
		t.Fatal(err)
	}
	removed, err := m.Uninstall(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	next := removed
	next.State, next.Rule = "installing", nil
	next.ServiceHash, next.SocketHash = "", ""
	next.PreviousServiceHash, next.PreviousSocketHash = "", ""
	delete(next.DirectoryIDs, "app")
	if err := m.saveOperation(Operation{Kind: "install", Stage: "prepared", Bundle: bundle, Release: *next.ReleaseMetadata, Reinstallation: &next}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(m.Layout.app()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery fixture unexpectedly installed files: %v", err)
	}
	recovered, err := m.Recover(ctx)
	if err != nil || recovered.State != "installed" || recovered.Pin != removed.Pin || recovered.Config != removed.Config || fake.socket == nil {
		t.Fatalf("reinstall recovery: %s %v", recovered.State, err)
	}
	_, op, err := m.Status()
	if err != nil || op.Stage != "complete" {
		t.Fatalf("reinstall recovery did not finish journal: %v", err)
	}
	if _, err := m.Recover(ctx); err != nil {
		t.Fatalf("completed reinstall recovery is not idempotent: %v", err)
	}
}
