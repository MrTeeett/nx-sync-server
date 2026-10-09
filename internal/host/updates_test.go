package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/release"
	"nx-sync-server/internal/store"
)

func TestUpdateScheduleIsOptInAndOwnsOnlyItsUnits(t *testing.T) {
	m, fake, man, _ := installed(t)
	policy, err := m.UpdatePolicy()
	if err != nil || policy.Enabled || policy.Channel != "stable" || policy.IntervalSeconds != 86400 {
		t.Fatalf("default policy: %+v %v", policy, err)
	}
	policy, err = m.ConfigureUpdates(context.Background(), UpdatePolicy{Enabled: true, Channel: "dev", IntervalSeconds: 7200, AllowUnsigned: true})
	if err != nil || !policy.Enabled || policy.InstallationID != man.InstallationID {
		t.Fatalf("configured policy: %+v %v", policy, err)
	}
	timer, err := os.ReadFile(m.updateTimerPath())
	if err != nil || !strings.Contains(string(timer), "OnUnitInactiveSec=7200s") {
		t.Fatalf("timer: %s %v", timer, err)
	}
	for _, call := range fake.calls {
		if strings.Contains(call, "nginx") {
			t.Fatal("modified foreign service")
		}
	}
	if err := os.WriteFile(m.updateServicePath(), []byte("foreign contents"), 0644); err != nil {
		t.Fatal(err)
	}
	before := len(fake.calls)
	if _, err := m.ConfigureUpdates(context.Background(), UpdatePolicy{Channel: "stable", IntervalSeconds: 86400}); err == nil {
		t.Fatal("replaced an unrecognized service file")
	}
	if len(fake.calls) != before {
		t.Fatal("issued systemd changes for a foreign service file")
	}
}

func TestFailedOnlineUpdateRestoresBinaryWithoutRestoringDatabase(t *testing.T) {
	m, fake, initial, key := installed(t)
	ctx := context.Background()
	s, err := store.Open(ctx, initial.Config.Database, limits(initial.Config))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := s.Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	bundle := t.TempDir()
	for _, name := range []string{"nx-syncd", "nx-syncctl"} {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte("replacement"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := release.Sign(bundle, "0.1.1", config.Target(), 2, time.Now().Add(time.Hour), key); err != nil {
		t.Fatal(err)
	}
	fake.failStartOnce = true
	restored, err := m.UpdateWithOptions(ctx, UpdateOptions{Bundle: bundle, RollbackOnFailure: true})
	if err == nil || restored.Version != initial.Version || restored.Sequence != initial.Sequence || restored.HighestSequence != 2 {
		t.Fatalf("rollback: %+v %v", restored, err)
	}
	_, operation, err := m.Status()
	if err != nil || operation.Stage != "complete" || operation.Kind != "rollback" || fake.socket == nil {
		t.Fatalf("recovery state: %+v %v", operation, err)
	}
	s, err = store.Open(ctx, initial.Config.Database, limits(initial.Config))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after, err := s.Identity(ctx)
	if err != nil || after != identity {
		t.Fatalf("database identity changed on rollback: %+v %v", after, err)
	}
	if _, err := m.Update(ctx, bundle); err == nil {
		t.Fatal("retried a known failed release")
	}
}

func TestRollbackRefusesChangedRetainedBinary(t *testing.T) {
	m, _, initial, key := installed(t)
	bundle := t.TempDir()
	for _, name := range []string{"nx-syncd", "nx-syncctl"} {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte("new"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := release.Sign(bundle, "0.1.1", config.Target(), 2, time.Now().Add(time.Hour), key); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Update(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.Layout.binaryDir(initial.Sequence), "nx-syncd"), []byte("changed"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Rollback(context.Background()); err == nil {
		t.Fatal("activated a modified retained executable")
	}
}

func TestDisabledAutomaticUpdateDoesNotFetch(t *testing.T) {
	m, _, _, _ := installed(t)
	result, err := m.AutoUpdate(context.Background())
	if err != nil || result.Updated {
		t.Fatalf("disabled updater: %+v %v", result, err)
	}
	if _, err := os.Lstat(filepath.Join(m.Layout.meta(), "update-state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("disabled updater performed an update check")
	}
}
