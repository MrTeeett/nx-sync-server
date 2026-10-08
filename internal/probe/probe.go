package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"nx-sync-server/internal/config"
	"nx-sync-server/internal/fsutil"
	"nx-sync-server/internal/protocol"
	"nx-sync-server/internal/tlsutil"
	"time"
)

type Result struct {
	Ready           bool  `json:"ready"`
	ElapsedMillis   int64 `json:"elapsed_ms"`
	ProtocolVersion int   `json:"protocol_version"`
}

func Check(ctx context.Context, endpoint, pin, proxy string) (Result, error) {
	return check(ctx, endpoint, pin, proxy, "")
}

// Local checks the owned listener without relying on external routing or DNS.
// The HTTPS origin still provides the SAN and the pinned identity checks.
func Local(ctx context.Context, endpoint, pin, address string) (Result, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return Result{}, errors.New("invalid local probe address")
	}
	return check(ctx, endpoint, pin, "", address)
}

func check(ctx context.Context, endpoint, pin, proxy, address string) (Result, error) {
	var result Result
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return result, errors.New("endpoint must be a plain HTTPS origin")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
	if pin != "" {
		tlsConfig, err = tlsutil.PinnedConfig(u.Hostname(), pin)
		if err != nil {
			return result, err
		}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, MaxResponseHeaderBytes: 4096, DisableKeepAlives: true}
	if address != "" {
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
		}
	}
	if proxy != "" {
		p, e := url.Parse(proxy)
		if e != nil || p.Host == "" || p.User != nil || (p.Scheme != "http" && p.Scheme != "https") {
			return result, errors.New("invalid explicit proxy")
		}
		transport.Proxy = http.ProxyURL(p)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u.Path = "/health"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return result, err
	}
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return result, fmt.Errorf("HTTPS probe failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 && response.StatusCode != 503 {
		return result, errors.New("unexpected health HTTP status")
	}
	var health protocol.Health
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 {
		return result, errors.New("oversized NX health response")
	}
	if err = fsutil.DecodeJSON(bytes.NewReader(body), &health); err != nil {
		return result, errors.New("invalid NX health response")
	}
	if health.ProtocolVersion != config.ProtocolVersion || (health.Status != "ready" && health.Status != "not_ready") || (response.StatusCode == 200) != (health.Status == "ready") {
		return result, errors.New("incompatible NX health response")
	}
	result = Result{Ready: health.Status == "ready", ElapsedMillis: time.Since(start).Milliseconds(), ProtocolVersion: health.ProtocolVersion}
	return result, nil
}
