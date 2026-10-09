package updates

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLatestDoesNotFallBackFromStableToDev(t *testing.T) {
	requests := 0
	c := &Client{HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		if !strings.HasSuffix(r.URL.Path, "/latest") {
			t.Fatalf("unexpected fallback: %s", r.URL)
		}
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}
	if _, err := c.Latest(context.Background(), "stable", "linux-amd64"); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("missing stable release: %v", err)
	}
	if requests != 1 {
		t.Fatalf("made %d requests", requests)
	}
}

func TestLatestRequiresSelectedChannelAndExactRepositoryAssets(t *testing.T) {
	for _, test := range []struct {
		name, tag, channel string
		prerelease         bool
		malicious          bool
		valid              bool
	}{
		{"stable", "v0.1.0", "stable", false, false, true},
		{"dev", "dev", "dev", true, false, true},
		{"prerelease as stable", "v0.1.0", "stable", true, false, false},
		{"wrong dev tag", "v0.2.0", "dev", true, false, false},
		{"foreign archive", "v0.1.0", "stable", false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			prefix := "https://github.com/" + Repository + "/releases/download/" + test.tag + "/"
			if test.malicious {
				prefix = "https://example.com/"
			}
			data, err := json.Marshal(map[string]any{"tag_name": test.tag, "prerelease": test.prerelease, "draft": false, "assets": []Asset{
				{Name: "nx-sync-server-linux-amd64.tar.gz", URL: prefix + "nx-sync-server-linux-amd64.tar.gz", Size: 1},
				{Name: "SHA256SUMS", URL: prefix + "SHA256SUMS", Size: 1},
			}})
			if err != nil {
				t.Fatal(err)
			}
			c := &Client{HTTP: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data))}, nil
			})}}
			_, err = c.Latest(context.Background(), test.channel, "linux-amd64")
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
		})
	}
}

func TestArchiveRejectsTraversalLinksAndDuplicateBinaries(t *testing.T) {
	for _, unsafe := range []tar.Header{
		{Name: "linux-amd64/../../escape", Typeflag: tar.TypeReg},
		{Name: "linux-amd64/nx-syncd", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "linux-amd64/nx-syncd", Typeflag: tar.TypeReg, Size: 1},
	} {
		directory := t.TempDir()
		var buffer bytes.Buffer
		compressed := gzip.NewWriter(&buffer)
		archive := tar.NewWriter(compressed)
		for _, name := range []string{"nx-syncd", "nx-syncctl", "release.json"} {
			if err := archive.WriteHeader(&tar.Header{Name: "linux-amd64/" + name, Typeflag: tar.TypeReg, Size: 1}); err != nil {
				t.Fatal(err)
			}
			if _, err := archive.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		if err := archive.WriteHeader(&unsafe); err != nil {
			t.Fatal(err)
		}
		if unsafe.Size == 1 {
			if _, err := archive.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
		if err := compressed.Close(); err != nil {
			t.Fatal(err)
		}
		if err := extract(bytes.NewReader(buffer.Bytes()), directory, "linux-amd64"); err == nil {
			t.Fatalf("accepted unsafe archive member: %+v", unsafe)
		}
		if _, err := os.Lstat(filepath.Join(directory, "escape")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("wrote an unselected archive member")
		}
	}
}

func TestDownloadURLsRejectHTTPUserinfoAndForeignHosts(t *testing.T) {
	for _, raw := range []string{"http://github.com/", "https://user@github.com/", "https://github.com:8443/", "https://github.com.evil.example/"} {
		if allowedURL(raw) {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestStableDowngradeComparesNumericComponents(t *testing.T) {
	for _, test := range []struct {
		next, current string
		downgrade     bool
	}{
		{"v1.9.0", "1.10.0", true},
		{"v2.0.0", "1.99.99", false},
		{"1.0.0", "1.0.0", false},
		{"0.1.0", "0.1.0-dev.123", false},
		{"9.0.0", "999999999999999999999999999999.0.0", true},
	} {
		if got := IsStableDowngrade(test.next, test.current); got != test.downgrade {
			t.Fatalf("%s -> %s: downgrade=%v", test.current, test.next, got)
		}
	}
}
