package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nx-sync-server/internal/tlsutil"
)

func https(t *testing.T, handler http.HandlerFunc) (string, string) {
	t.Helper()
	dir := t.TempDir()
	key, cert := filepath.Join(dir, "key"), filepath.Join(dir, "cert")
	pin, err := tlsutil.Create(key, cert, "127.0.0.1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := tlsutil.Load(key, cert, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: handler, TLSConfig: manager.Config()}
	done := make(chan struct{})
	go func() { _ = s.Serve(tls.NewListener(l, manager.Config())); close(done) }()
	t.Cleanup(func() { _ = s.Close(); <-done })
	return "https://" + l.Addr().String(), pin
}

func TestHTTPSAvailabilityTrustAndBounds(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		want       bool
		bad        bool
	}{
		{"ready", `{"protocol_version":1,"status":"ready"}`, 200, true, false},
		{"storage unavailable", `{"protocol_version":1,"status":"not_ready"}`, 503, false, false},
		{"wrong version", `{"protocol_version":2,"status":"ready"}`, 200, false, true},
		{"inconsistent status", `{"protocol_version":1,"status":"ready"}`, 503, false, true},
		{"oversized padding", `{"protocol_version":1,"status":"ready"}` + strings.Repeat(" ", 5000), 200, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint, pin := https(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					t.Error("wrong path")
				}
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			})
			r, err := Check(context.Background(), endpoint, pin, "")
			if (err != nil) != test.bad || err == nil && r.Ready != test.want {
				t.Fatalf("result=%+v err=%v", r, err)
			}
			if _, err = Check(context.Background(), endpoint, strings.Repeat("0", 64), ""); err == nil {
				t.Fatal("incorrect pin accepted")
			}
		})
	}
}

func TestRedirectProxyFailureAndCancellation(t *testing.T) {
	endpoint, pin := https(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://example.invalid", 302) })
	if _, err := Check(context.Background(), endpoint, pin, ""); err == nil {
		t.Fatal("redirect followed")
	}
	if _, err := Check(context.Background(), endpoint, pin, "http://127.0.0.1:1"); err == nil {
		t.Fatal("failed proxy fell back to direct")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := Check(ctx, endpoint, pin, ""); err == nil || time.Since(start) > time.Second {
		t.Fatalf("cancellation err=%v", err)
	}
}

func TestRenewalKeepsIdentityAndSAN(t *testing.T) {
	dir := t.TempDir()
	key, cert := filepath.Join(dir, "key"), filepath.Join(dir, "cert")
	pin, err := tlsutil.Create(key, cert, "127.0.0.1", time.Now().Add(-70*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	m, err := tlsutil.Load(key, cert, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.RenewIfNeeded(time.Now()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	newPin, err := tlsutil.ReadFingerprint(cert)
	if err != nil || newPin != pin || string(before) == string(after) {
		t.Fatalf("renewal pin=%s err=%v", newPin, err)
	}
	if _, err = tlsutil.Load(key, cert, "wrong.example"); err == nil {
		t.Fatal("incorrect SAN accepted")
	}
}
