package updates

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"nx-sync-server/internal/fsutil"
	"nx-sync-server/internal/release"
)

const Repository = "MrTeeett/nx-sync-server"
const MaxArchiveBytes int64 = 256 << 20

var ErrNoRelease = errors.New("no release is published for the selected channel; dev must be selected explicitly")

var stableVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// IsStableDowngrade compares numeric version components without integer
// overflow. A dev installation may explicitly switch to a stable channel.
func IsStableDowngrade(next, current string) bool {
	next = strings.TrimPrefix(next, "v")
	if !stableVersion.MatchString(next) || !stableVersion.MatchString(current) {
		return false
	}
	a, b := strings.Split(next, "."), strings.Split(current, ".")
	for i := range a {
		left, right := strings.TrimLeft(a[i], "0"), strings.TrimLeft(b[i], "0")
		if len(left) != len(right) {
			return len(left) < len(right)
		}
		if left != right {
			return left < right
		}
	}
	return false
}

type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

type Candidate struct {
	Tag       string `json:"tag"`
	Channel   string `json:"channel"`
	Target    string `json:"target"`
	Archive   Asset  `json:"archive"`
	Checksums Asset  `json:"checksums"`
}

type Client struct{ HTTP *http.Client }

func allowedURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" && u.Port() != "443" {
		return false
	}
	switch u.Hostname() {
	case "api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	default:
		return false
	}
}

func New() *Client {
	return &Client{HTTP: &http.Client{
		Timeout: 3 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 || !allowedURL(req.URL.String()) {
				return errors.New("untrusted release redirect")
			}
			return nil
		},
	}}
}

func (c *Client) get(ctx context.Context, raw string) (*http.Response, error) {
	if !allowedURL(raw) {
		return nil, errors.New("untrusted release URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nx-syncctl")
	req.Header.Set("Accept", "application/vnd.github+json")
	response, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		if response.StatusCode == http.StatusNotFound {
			return nil, ErrNoRelease
		}
		return nil, fmt.Errorf("GitHub release request returned HTTP %d", response.StatusCode)
	}
	return response, nil
}

func (c *Client) Latest(ctx context.Context, channel, target string) (Candidate, error) {
	var candidate Candidate
	if _, err := release.Architecture(target); err != nil {
		return candidate, err
	}
	suffix := "/latest"
	if channel == "dev" {
		suffix = "/tags/dev"
	} else if channel != "stable" {
		return candidate, errors.New("channel must be stable or dev")
	}
	response, err := c.get(ctx, "https://api.github.com/repos/"+Repository+"/releases"+suffix)
	if err != nil {
		return candidate, err
	}
	defer response.Body.Close()
	data, err := fsutil.ReadBounded(response.Body, 1<<20)
	if err != nil {
		return candidate, err
	}
	var document struct {
		Tag        string  `json:"tag_name"`
		Draft      bool    `json:"draft"`
		Prerelease bool    `json:"prerelease"`
		Assets     []Asset `json:"assets"`
	}
	if err = json.Unmarshal(data, &document); err != nil {
		return candidate, err
	}
	if document.Draft || channel == "dev" && (document.Tag != "dev" || !document.Prerelease) || channel == "stable" && (document.Prerelease || !stableVersion.MatchString(strings.TrimPrefix(document.Tag, "v"))) {
		return candidate, errors.New("release does not match selected channel")
	}
	candidate = Candidate{Tag: document.Tag, Channel: channel, Target: target}
	archive := "nx-sync-server-" + target + ".tar.gz"
	for _, asset := range document.Assets {
		if asset.Name != archive && asset.Name != "SHA256SUMS" {
			continue
		}
		expected := "https://github.com/" + Repository + "/releases/download/" + document.Tag + "/" + asset.Name
		if asset.URL != expected || asset.Size < 1 {
			return Candidate{}, errors.New("invalid release asset")
		}
		if asset.Name == archive {
			if candidate.Archive.Name != "" || asset.Size > MaxArchiveBytes {
				return Candidate{}, errors.New("invalid or duplicate release archive")
			}
			candidate.Archive = asset
		} else {
			if candidate.Checksums.Name != "" || asset.Size > 64<<10 {
				return Candidate{}, errors.New("invalid release checksums")
			}
			candidate.Checksums = asset
		}
	}
	if candidate.Archive.Name == "" || candidate.Checksums.Name == "" {
		return Candidate{}, errors.New("release is missing the architecture archive or checksums")
	}
	return candidate, nil
}

// Download never executes an archive member. Callers verify release.json and
// artifact hashes before handing the directory to the installation manager.
func (c *Client) Download(ctx context.Context, candidate Candidate, parent string) (_ string, err error) {
	checks, err := c.get(ctx, candidate.Checksums.URL)
	if err != nil {
		return "", err
	}
	data, readErr := fsutil.ReadBounded(checks.Body, 64<<10)
	closeErr := checks.Body.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	expected := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == candidate.Archive.Name {
			if expected != "" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fields[0]) {
				return "", errors.New("invalid archive checksum")
			}
			expected = fields[0]
		}
	}
	if expected == "" || candidate.Archive.Digest != "" && candidate.Archive.Digest != "sha256:"+expected {
		return "", errors.New("archive checksum is absent or inconsistent")
	}
	dir, err := os.MkdirTemp(parent, "download-")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	archive, err := os.OpenFile(filepath.Join(dir, "archive.tar.gz"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	response, err := c.get(ctx, candidate.Archive.URL)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(archive, hash), io.LimitReader(response.Body, MaxArchiveBytes+1))
	closeErr = response.Body.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if count != candidate.Archive.Size || count > MaxArchiveBytes || hex.EncodeToString(hash.Sum(nil)) != expected {
		return "", errors.New("release archive size or checksum mismatch")
	}
	if _, err = archive.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	if err = extract(archive, dir, candidate.Target); err != nil {
		return "", err
	}
	if err = archive.Close(); err != nil {
		return "", err
	}
	if err = os.Remove(filepath.Join(dir, "archive.tar.gz")); err != nil {
		return "", err
	}
	return dir, nil
}

func extract(input io.Reader, directory, target string) error {
	gzipReader, err := gzip.NewReader(input)
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	reader := tar.NewReader(io.LimitReader(gzipReader, 320<<20))
	seen := map[string]bool{}
	for entries := 0; ; entries++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(header.Name, "/")
		if entries >= 512 || strings.Contains(name, "\\") || name != target && !strings.HasPrefix(name, target+"/") || filepath.Clean(name) != name || header.Size < 0 || header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg {
			return errors.New("unsafe release archive member")
		}
		relative := strings.TrimPrefix(name, target+"/")
		if relative != "nx-syncd" && relative != "nx-syncctl" && relative != "release.json" {
			continue
		}
		limit := int64(128 << 20)
		if relative == "release.json" {
			limit = 64 << 10
		}
		if seen[relative] || header.Typeflag != tar.TypeReg || header.Size < 1 || header.Size > limit {
			return errors.New("invalid release archive member")
		}
		seen[relative] = true
		file, err := os.OpenFile(filepath.Join(directory, relative), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		count, writeErr := io.Copy(file, io.LimitReader(reader, limit+1))
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		if count != header.Size {
			return errors.New("truncated release archive member")
		}
	}
	if len(seen) != 3 {
		return errors.New("release archive is missing binaries or metadata")
	}
	return nil
}
