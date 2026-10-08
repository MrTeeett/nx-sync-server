package api

import (
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

func TestHTTPAuthSignedWriteAndBoundedHealth(t *testing.T) {
	c := config.Defaults()
	ctx := context.Background()
	s, err := store.Create(ctx, filepath.Join(t.TempDir(), "db"), store.Limits{EnvelopeBytes: c.MaxEnvelopeBytes, ProfileBytes: c.MaxProfileBytes, Devices: c.MaxDevices})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.Bootstrap(ctx, pub, pub)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	control := protocol.Control{ProfileID: credential.ProfileID, Generation: credential.Generation, OperationID: operation, KeyEpoch: 1, ModeEpoch: 1, CipherMode: "e2ee", OwnerDeviceID: credential.DeviceID, OwnerPublicKey: pub, Members: []protocol.Member{{DeviceID: credential.DeviceID, PublicKey: pub, Role: "writer"}}}
	control.Signature = ed25519.Sign(key, control.SigningBytes())
	if _, err = s.PutControl(ctx, credential.Token, control); err != nil {
		t.Fatal(err)
	}
	h := New(s, c)
	request := func(method, path, body string, auth bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if auth {
			r.Header.Set("Authorization", "Bearer "+credential.Token)
			r.Header.Set("X-NX-Generation", credential.Generation)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := request("GET", "/health", "", false)
	if w.Code != 200 || w.Body.Len() > 128 || strings.Contains(w.Body.String(), credential.ProfileID) {
		t.Fatalf("health: %d %s", w.Code, w.Body.String())
	}
	path := "/v1/profiles/" + credential.ProfileID + "/envelopes/" + credential.DeviceID
	if w = request("GET", path, "", false); w.Code != 401 {
		t.Fatalf("unauthorized: %d", w.Code)
	}
	operation, err = protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	e := protocol.Envelope{ProfileID: credential.ProfileID, DeviceID: credential.DeviceID, Generation: credential.Generation, OperationID: operation, Sequence: 1, KeyEpoch: 1, ModeEpoch: 1, CipherMode: "e2ee", Payload: []byte("opaque")}
	e.Signature = ed25519.Sign(key, e.SigningBytes())
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if w = request("PUT", path, string(data), true); w.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", w.Code, w.Body.String())
	}
	if w = request("GET", path, "", true); w.Code != 200 || w.Header().Get("ETag") != `"1"` {
		t.Fatalf("read: %d %s", w.Code, w.Body.String())
	}
	if w = request("PUT", path, `{"unexpected":true}`, true); w.Code != 400 {
		t.Fatalf("unknown fields: %d", w.Code)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if w = request("GET", "/health", "", false); w.Code != 503 || !strings.Contains(w.Body.String(), "not_ready") {
		t.Fatalf("unavailable health: %d %s", w.Code, w.Body.String())
	}
}
