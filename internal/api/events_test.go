package api

import (
	"bufio"
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
	"time"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/protocol"
	"nx-sync-server/internal/store"
)

func TestEventHintsDoNotStarveRequestsAndCloseOnProfileDeletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := config.Defaults()
	c.MaxRequests = 1
	c.MaxConnections = 2
	s, err := store.Create(ctx, filepath.Join(t.TempDir(), "db"), store.Limits{
		EnvelopeBytes: c.MaxEnvelopeBytes, ProfileBytes: c.MaxProfileBytes, Devices: c.MaxDevices,
	})
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
	control := protocol.Control{
		ProfileID: credential.ProfileID, Generation: credential.Generation, OperationID: operation,
		KeyEpoch: 1, ModeEpoch: 1, CipherMode: "e2ee", OwnerDeviceID: credential.DeviceID, OwnerPublicKey: pub,
		Members: []protocol.Member{{DeviceID: credential.DeviceID, PublicKey: pub, Role: "writer"}},
	}
	control.Signature = ed25519.Sign(key, control.SigningBytes())
	if _, err = s.PutControl(ctx, credential.Token, control); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(s, c))
	defer server.Close()
	client := server.Client()
	profilePath := "/v1/profiles/" + credential.ProfileID
	request := func(method, path string, value any, authenticated bool) *http.Response {
		t.Helper()
		var body []byte
		if value != nil {
			body, err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
		}
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if value != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+credential.Token)
			r.Header.Set("X-NX-Generation", credential.Generation)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	unauthenticated := request("GET", profilePath+"/events", nil, false)
	unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stream: %d", unauthenticated.StatusCode)
	}
	stream := request("GET", profilePath+"/events", nil, true)
	defer stream.Body.Close()
	if stream.StatusCode != http.StatusOK || stream.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream headers: %d %v", stream.StatusCode, stream.Header)
	}
	scanner := bufio.NewScanner(stream.Body)
	readHint := func() string {
		t.Helper()
		if !scanner.Scan() || scanner.Text() != "event: changed" || !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "data: ") {
			t.Fatalf("missing change hint: %v", scanner.Err())
		}
		var hint map[string]string
		if err := json.Unmarshal([]byte(strings.TrimPrefix(scanner.Text(), "data: ")), &hint); err != nil {
			t.Fatal(err)
		}
		if len(hint) != 1 || len(hint["etag"]) != 66 || !scanner.Scan() || scanner.Text() != "" {
			t.Fatalf("hint must contain only a state cursor: %v", hint)
		}
		return hint["etag"]
	}
	initial := readHint()
	state := request("GET", profilePath+"/state", nil, true)
	state.Body.Close()
	if state.StatusCode != http.StatusOK || state.Header.Get("ETag") != initial {
		t.Fatalf("state request was starved or initial cursor differs: %d", state.StatusCode)
	}
	operation, err = protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	envelope := protocol.Envelope{
		ProfileID: credential.ProfileID, DeviceID: credential.DeviceID, Generation: credential.Generation,
		OperationID: operation, Sequence: 1, KeyEpoch: 1, ModeEpoch: 1, CipherMode: "e2ee", Payload: []byte("opaque"),
	}
	envelope.Signature = ed25519.Sign(key, envelope.SigningBytes())
	published := request("PUT", profilePath+"/envelopes/"+credential.DeviceID, envelope, true)
	published.Body.Close()
	if published.StatusCode != http.StatusOK {
		t.Fatalf("publish with an active stream: %d", published.StatusCode)
	}
	if updated := readHint(); updated == initial {
		t.Fatal("committed write did not change the state cursor")
	}
	control.OperationID, err = protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	control.ExpectedRevision = 1
	control.Closed = true
	control.KeyEpoch++
	control.Signature = ed25519.Sign(key, control.SigningBytes())
	deleted := request("PUT", profilePath+"/control", control, true)
	deleted.Body.Close()
	if deleted.StatusCode != http.StatusOK {
		t.Fatalf("close profile: %d", deleted.StatusCode)
	}
	if scanner.Scan() || scanner.Err() != nil {
		t.Fatalf("closed profile kept its event stream open: %v", scanner.Err())
	}
}

func TestSlowEventConsumerCoalescesHintsAndUnsubscribes(t *testing.T) {
	hub := new(eventHub)
	changes, unsubscribe := hub.subscribe("profile")
	other, removeOther := hub.subscribe("other")
	defer removeOther()
	for range 1000 {
		hub.changed("profile")
	}
	if len(changes) != 1 || len(other) != 0 {
		t.Fatal("hints must be bounded and isolated per profile")
	}
	<-changes
	unsubscribe()
	unsubscribe()
	hub.changed("profile")
	if len(changes) != 0 {
		t.Fatal("disconnected subscriber still receives changes")
	}
}
