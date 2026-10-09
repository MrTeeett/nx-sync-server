package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/fsutil"
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

func TestUnsignedRequiresAcknowledgementAndStillChecksMetadata(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, name := range []string{"nx-syncd", "nx-syncctl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if err := Sign(dir, "0.1.0", config.Target(), 4, now.Add(time.Hour), key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "release.json")
	var manifest Signed
	if err := fsutil.ReadJSON(path, &manifest, 64<<10); err != nil {
		t.Fatal(err)
	}
	var metadata Metadata
	if err := json.Unmarshal(manifest.Payload, &metadata); err != nil {
		t.Fatal(err)
	}
	metadata.Channel, metadata.Version = "dev", "0.1.0-dev.abcdef"
	write := func(value Metadata) {
		t.Helper()
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := fsutil.WriteJSON(path, Signed{Payload: payload}, 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(metadata)
	if _, err := Verify(path, "", 3, now); err == nil || !strings.Contains(err.Error(), "--allow-unsigned") {
		t.Fatalf("unsigned release must require acknowledgement: %v", err)
	}
	verified, err := Inspect(path, "", 3, now, true)
	if err != nil || verified.Signed || verified.Metadata.Version != metadata.Version {
		t.Fatalf("acknowledged dev release without a key: %+v, %v", verified, err)
	}
	if err := CheckArtifacts(dir, verified.Metadata); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(path, "", 4, now, true); err == nil {
		t.Fatal("unsigned release replay accepted")
	}
	if _, err := Inspect(path, "", 3, now.Add(2*time.Hour), true); err == nil {
		t.Fatal("expired unsigned release accepted")
	}
	for _, mutate := range []func(*Metadata){
		func(m *Metadata) { m.Target = "linux-unknown" },
		func(m *Metadata) { m.Architecture = "unknown" },
		func(m *Metadata) { m.Schema++ },
		func(m *Metadata) { m.Artifacts[0].Name = "../../foreign" },
	} {
		changed := metadata
		changed.Artifacts = append([]Artifact(nil), metadata.Artifacts...)
		mutate(&changed)
		write(changed)
		if _, err := Inspect(path, "", 3, now, true); err == nil {
			t.Fatal("unsigned acknowledgement bypassed compatibility checks")
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "nx-syncd"), []byte("modified"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := CheckArtifacts(dir, verified.Metadata); err == nil {
		t.Fatal("unsigned acknowledgement bypassed artifact checks")
	}
}

func TestUnsignedAcknowledgementNeverBypassesPresentSignature(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, name := range []string{"nx-syncd", "nx-syncctl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := Sign(dir, "0.1.0", config.Target(), 4, time.Now().Add(time.Hour), key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "release.json")
	trust := base64.StdEncoding.EncodeToString(pub)
	if _, err := Inspect(path, "", 0, time.Now(), true); err == nil {
		t.Fatal("present signature accepted without a publisher key")
	}
	verified, err := Inspect(path, trust, 0, time.Now(), true)
	if err != nil || !verified.Signed {
		t.Fatalf("signed package lost publisher verification: %v", err)
	}
	var manifest Signed
	if err := fsutil.ReadJSON(path, &manifest, 64<<10); err != nil {
		t.Fatal(err)
	}
	manifest.Signature[0] ^= 1
	if err := fsutil.WriteJSON(path, manifest, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(path, trust, 0, time.Now(), true); err == nil {
		t.Fatal("invalid signature fell back to unsigned installation")
	}
	manifest.Signature = []byte{1}
	if err := fsutil.WriteJSON(path, manifest, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(path, trust, 0, time.Now(), true); err == nil {
		t.Fatal("truncated signature fell back to unsigned installation")
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
