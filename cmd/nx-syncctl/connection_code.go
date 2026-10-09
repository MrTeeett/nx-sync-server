package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/fsutil"
	"nx-sync-server/internal/store"
	"nx-sync-server/internal/tlsutil"
)

func newConnectionCode(ctx context.Context, path, endpoint string) (string, int64, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(endpoint, "\r\n\\") {
		return "", 0, errors.New("endpoint must be an HTTPS origin")
	}
	c, err := config.Load(path)
	if err != nil {
		return "", 0, err
	}
	pin, err := tlsutil.ReadFingerprint(c.TLSCertificate)
	if err != nil {
		return "", 0, err
	}
	s, err := store.Open(ctx, c.Database, store.Limits{EnvelopeBytes: c.MaxEnvelopeBytes, ProfileBytes: c.MaxProfileBytes, Devices: c.MaxDevices})
	if err != nil {
		return "", 0, err
	}
	defer s.Close()
	ticket, identity, expires, err := s.NewBootstrapTicket(ctx)
	if err != nil {
		return "", 0, err
	}
	code := struct {
		Version    int    `json:"version"`
		Kind       string `json:"kind"`
		Endpoint   string `json:"endpoint"`
		Pin        string `json:"pin"`
		Generation string `json:"generation"`
		Ticket     string `json:"ticket"`
		Expires    int64  `json:"expires_at,string"`
	}{1, "bootstrap", strings.TrimSuffix(u.String(), "/"), pin, identity.Generation, ticket, expires}
	data, err := json.Marshal(code)
	if err != nil {
		return "", 0, err
	}
	return "nxsync1:" + base64.RawURLEncoding.EncodeToString(data), expires, nil
}

func connectionCode(ctx context.Context, args []string) error {
	f := flags("connection-code")
	path := f.String("config", "/etc/nx-syncd/config.json", "local configuration")
	endpoint := f.String("endpoint", "", "public HTTPS origin, including the selected port")
	out := f.String("out", "", "new private file; - explicitly returns the secret code over trusted SSH")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required")
	}
	printCode := false
	if *out == "-" {
		printCode = true
	}
	code, expires, err := newConnectionCode(ctx, *path, *endpoint)
	if err != nil {
		return err
	}
	if printCode {
		return output(map[string]any{"connection_code": code, "expires_at": expires})
	}
	if err = exclusive(*out, nil); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(*out)
		}
	}()
	if err = fsutil.AtomicWrite(*out, []byte(code+"\n"), 0600); err != nil {
		return err
	}
	complete = true
	return output(map[string]any{"code_file": *out, "expires_at": expires, "single_use": true})
}
