package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"nx-sync-server/internal/protocol"
)

func TestStateResumeWithLostLocalCheckpoint(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	read := func(credential Credential) *protocol.Head {
		t.Helper()
		state, err := f.s.State(ctx, credential.ProfileID, credential.Generation, credential.Token)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		var response struct {
			Resume *struct {
				DeviceID string         `json:"device_id"`
				Head     *protocol.Head `json:"head"`
			} `json:"resume"`
		}
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatal(err)
		}
		if response.Resume == nil || response.Resume.DeviceID != credential.DeviceID {
			t.Fatal("state must offer recovery for the authenticated device")
		}
		return response.Resume.Head
	}
	if head := read(f.credential); head != nil {
		t.Fatal("a new device has no committed envelope to recover")
	}
	envelope := f.envelope(t)
	envelope.Sequence = 35
	envelope.Signature = ed25519.Sign(f.deviceKey, envelope.SigningBytes())
	if _, err := f.s.Publish(ctx, f.credential.Token, envelope); err != nil {
		t.Fatal(err)
	}
	head := read(f.credential)
	if head == nil || head.DeviceID != envelope.DeviceID || head.Sequence != 35 || head.Revision != 1 || head.Hash == "" {
		t.Fatalf("lost checkpoint recovery head: %+v", head)
	}
	stale := f.envelope(t)
	if _, err := f.s.Publish(ctx, f.credential.Token, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("recovery must retain stale-write rejection: %v", err)
	}
	stale.ExpectedRevision = head.Revision
	stale.Sequence = head.Sequence + 1
	stale.Signature = ed25519.Sign(f.deviceKey, stale.SigningBytes())
	if receipt, err := f.s.Publish(ctx, f.credential.Token, stale); err != nil || receipt.Revision != 2 {
		t.Fatalf("resume with a newly signed next envelope: %+v %v", receipt, err)
	}
	pub, writer := keypair(t)
	control := f.control
	control.ExpectedRevision = 1
	peer := id(t)
	control.Members = append(append([]protocol.Member(nil), control.Members...), protocol.Member{DeviceID: peer, PublicKey: pub, Role: "writer"})
	if _, err := f.change(t, control); err != nil {
		t.Fatal(err)
	}
	credential, err := f.s.IssueCredential(ctx, control.ProfileID, peer)
	if err != nil {
		t.Fatal(err)
	}
	other := f.envelope(t)
	other.DeviceID = peer
	other.Sequence = 9
	other.Signature = ed25519.Sign(writer, other.SigningBytes())
	if _, err := f.s.Publish(ctx, credential.Token, other); err != nil {
		t.Fatal(err)
	}
	if head := read(credential); head == nil || head.DeviceID != peer || head.Sequence != 9 {
		t.Fatalf("resume must describe the requesting device, not another writer: %+v", head)
	}
	if _, err := f.s.State(ctx, credential.ProfileID, credential.Generation, "invalid"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unauthenticated recovery: %v", err)
	}
}
