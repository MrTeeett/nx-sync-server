package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/protocol"
	"nx-sync-server/internal/store"
)

func TestAccountManagementHTTPIsolationAndRevocation(t *testing.T) {
	ctx := context.Background()
	c := config.Defaults()
	c.Database = filepath.Join(t.TempDir(), "db")
	s, err := store.Create(ctx, c.Database, store.Limits{EnvelopeBytes: c.MaxEnvelopeBytes, ProfileBytes: c.MaxProfileBytes, Devices: c.MaxDevices})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := s.Bootstrap(ctx, pub, pub)
	if err != nil {
		t.Fatal(err)
	}
	guestPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := s.Bootstrap(ctx, guestPub, guestPub)
	if err != nil {
		t.Fatal(err)
	}
	h := New(s, c)
	request := func(method, path string, credential store.Credential, body any, etag string) *httptest.ResponseRecorder {
		var data []byte
		if body != nil {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+credential.Token)
		r.Header.Set("X-NX-Generation", credential.Generation)
		if etag != "" {
			r.Header.Set("If-None-Match", etag)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	ownerPath := "/v1/profiles/" + owner.ProfileID
	guestPath := "/v1/profiles/" + guest.ProfileID
	if w := request("GET", ownerPath+"/server", store.Credential{}, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("metadata without authentication: %d", w.Code)
	}
	w := request("GET", guestPath+"/server", guest, nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"owner":false`) || !strings.Contains(w.Body.String(), `"version":"`+config.Version+`"`) {
		t.Fatalf("guest info: %d %s", w.Code, w.Body.String())
	}
	w = request("POST", guestPath+"/server/device", guest, store.DeviceDescription{AccountLabel: "Other account", Label: "Phone", Platform: "android", Version: "12.10.1"}, "")
	if w.Code != 200 {
		t.Fatalf("client metadata: %d %s", w.Code, w.Body.String())
	}
	if w = request("GET", guestPath+"/server/accounts", guest, nil, ""); w.Code != 403 {
		t.Fatalf("guest list: %d", w.Code)
	}
	if w = request("GET", guestPath+"/server/administration", guest, nil, ""); w.Code != 403 {
		t.Fatalf("guest administration: %d", w.Code)
	}
	w = request("GET", ownerPath+"/server/accounts", owner, nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Other account") || strings.Contains(w.Body.String(), guest.Token) {
		t.Fatalf("owner list: %d", w.Code)
	}
	before := request("GET", guestPath+"/state", guest, nil, "")
	operation, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	command := protocol.ServerCommand{OperationID: operation, Target: guest.ProfileID}
	command.Signature = ed25519.Sign(key, command.SigningBytes("revoke", owner.ProfileID, owner.Generation))
	if w = request("POST", ownerPath+"/server/revoke", owner, command, ""); w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{guestPath + "/state", guestPath + "/server", guestPath + "/server/administration"} {
		w = request("GET", path, guest, nil, before.Header().Get("ETag"))
		if w.Code != 403 || !strings.Contains(w.Body.String(), "account_revoked") {
			t.Fatalf("revoked cached read: %d %s", w.Code, w.Body.String())
		}
	}
	if w = request("GET", ownerPath+"/server", owner, nil, ""); w.Code != 200 {
		t.Fatalf("owner retained: %d", w.Code)
	}
}
