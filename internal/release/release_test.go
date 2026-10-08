package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nx-sync-server/internal/config"
)

func TestPinnedPublisherHashExpiryAndSequence(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, name := range []string{"nx-syncd", "nx-syncctl"} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err = Sign(dir, "0.1.0", config.Target(), 4, time.Now().Add(time.Hour), key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "release.json")
	trust := base64.StdEncoding.EncodeToString(pub)
	metadata, err := Verify(path, trust, 3, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = CheckArtifacts(dir, metadata); err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(path, trust, 4, time.Now()); err == nil {
		t.Fatal("release replay accepted")
	}
	if _, err = Verify(path, trust, 3, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("expired metadata accepted")
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(path, base64.StdEncoding.EncodeToString(other), 3, time.Now()); err == nil {
		t.Fatal("wrong trust root accepted")
	}
	if err = os.WriteFile(filepath.Join(dir, "nx-syncd"), []byte("modified"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = CheckArtifacts(dir, metadata); err == nil {
		t.Fatal("modified artifact accepted")
	}
	if err = Sign(dir, "../unsafe", config.Target(), 5, time.Now().Add(time.Hour), key); err == nil {
		t.Fatal("invalid release version accepted")
	}
}

func TestTargetMatrixAgreesWithPublisher(t *testing.T) {
	data, err := os.ReadFile("../../packaging/targets.txt")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		arch, err := Architecture(fields[0])
		if err != nil || arch != fields[1] || seen[fields[0]] {
			t.Fatalf("invalid target %s: %v", line, err)
		}
		seen[fields[0]] = true
	}
	if len(seen) != 15 {
		t.Fatalf("expected full current Linux matrix, got %d", len(seen))
	}
}
