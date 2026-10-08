package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"nx-sync-server/internal/config"
	"nx-sync-server/internal/fsutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

type Artifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Metadata struct {
	Format       int        `json:"format"`
	Version      string     `json:"version"`
	Sequence     uint64     `json:"sequence,string"`
	Channel      string     `json:"channel"`
	OS           string     `json:"os"`
	Architecture string     `json:"architecture"`
	Target       string     `json:"target"`
	Schema       int        `json:"schema"`
	Expires      string     `json:"expires"`
	Artifacts    []Artifact `json:"artifacts"`
}
type Signed struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func Domain(payload []byte) []byte { return append([]byte("NX-SYNC-RELEASE\x00v1\x00"), payload...) }

func Verify(path, trustKey string, minSequence uint64, now time.Time) (Metadata, error) {
	var result Metadata
	var signed Signed
	key, err := base64.StdEncoding.DecodeString(trustKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return result, errors.New("trusted release public key required")
	}
	if err = fsutil.ReadJSON(path, &signed, 64<<10); err != nil {
		return result, err
	}
	if len(signed.Payload) > 32<<10 || !ed25519.Verify(key, Domain(signed.Payload), signed.Signature) {
		return result, errors.New("invalid release signature")
	}
	if err = fsutil.DecodeJSON(bytes.NewReader(signed.Payload), &result); err != nil {
		return result, err
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(canonical, signed.Payload) {
		return result, errors.New("release payload must use canonical field order/encoding")
	}
	expires, err := time.Parse(time.RFC3339, result.Expires)
	if err != nil || !expires.After(now) || expires.After(now.Add(90*24*time.Hour)) {
		return result, errors.New("expired or excessive release validity")
	}
	if result.Format != 1 || result.Sequence == 0 || result.Sequence <= minSequence || result.Channel != "stable" || result.OS != "linux" || result.Architecture != runtime.GOARCH || result.Target != config.Target() || result.Schema != 1 || !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(result.Version) || len(result.Version) > 64 || len(result.Artifacts) != 2 {
		return result, errors.New("incompatible or replayed release")
	}
	seen := map[string]bool{}
	for _, a := range result.Artifacts {
		hash, err := hex.DecodeString(a.SHA256)
		if (a.Name != "nx-syncd" && a.Name != "nx-syncctl") || seen[a.Name] || a.Size < 1 || a.Size > 128<<20 || err != nil || len(hash) != 32 {
			return result, errors.New("invalid release artifact")
		}
		seen[a.Name] = true
	}
	return result, nil
}

// Sign is an offline publisher operation. The installation helper never
// generates or learns the private release key.
func Sign(directory, version, target string, sequence uint64, expires time.Time, key ed25519.PrivateKey) error {
	arch, err := Architecture(target)
	if err != nil {
		return err
	}
	if sequence == 0 || !expires.After(time.Now()) || expires.After(time.Now().Add(90*24*time.Hour)) || !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version) || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid publisher metadata")
	}
	metadata := Metadata{Format: 1, Version: version, Sequence: sequence, Channel: "stable", OS: "linux", Architecture: arch, Target: target, Schema: 1, Expires: expires.UTC().Format(time.RFC3339)}
	for _, name := range []string{"nx-syncd", "nx-syncctl"} {
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 128<<20 {
			return errors.New("invalid publisher artifact")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(file, 128<<20+1))
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n != info.Size() {
			return errors.New("publisher artifact changed")
		}
		metadata.Artifacts = append(metadata.Artifacts, Artifact{Name: name, Size: n, SHA256: hex.EncodeToString(hash.Sum(nil))})
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return fsutil.WriteJSON(filepath.Join(directory, "release.json"), Signed{Payload: payload, Signature: ed25519.Sign(key, Domain(payload))}, 0644)
}

func Architecture(target string) (string, error) {
	switch target {
	case "linux-armv5", "linux-armv6", "linux-armv7":
		return "arm", nil
	case "linux-amd64", "linux-386", "linux-arm64", "linux-mips", "linux-mipsle", "linux-mips64", "linux-mips64le", "linux-ppc64", "linux-ppc64le", "linux-riscv64", "linux-s390x", "linux-loong64":
		return target[len("linux-"):], nil
	default:
		return "", errors.New("unsupported build target")
	}
}

func CheckArtifacts(directory string, metadata Metadata) error {
	for _, artifact := range metadata.Artifacts {
		path := filepath.Join(directory, artifact.Name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() != artifact.Size {
			return errors.New("invalid release artifact type/size")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, io.LimitReader(file, artifact.Size+1))
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
			return errors.New("release artifact hash mismatch")
		}
	}
	return nil
}
