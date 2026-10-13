package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"nx-sync-server/internal/protocol"
)

func TestClearSettingsPreservesConnectionsAndRetryPreservesNewCopy(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	peerPublic, peerKey := keypair(t)
	peerID := id(t)
	control := f.control
	control.Members = append([]protocol.Member(nil), control.Members...)
	control.Members = append(control.Members, protocol.Member{DeviceID: peerID, PublicKey: peerPublic, Role: "writer"})
	control.ExpectedRevision = 1
	if _, err := f.change(t, control); err != nil {
		t.Fatal(err)
	}
	peer, err := f.s.IssueCredential(ctx, control.ProfileID, peerID)
	if err != nil {
		t.Fatal(err)
	}
	ownerCopy := f.envelope(t)
	if _, err := f.s.Publish(ctx, f.credential.Token, ownerCopy); err != nil {
		t.Fatal(err)
	}
	peerCopy := f.envelope(t)
	peerCopy.DeviceID = peerID
	peerCopy.Signature = ed25519.Sign(peerKey, peerCopy.SigningBytes())
	if _, err := f.s.Publish(ctx, peer.Token, peerCopy); err != nil {
		t.Fatal(err)
	}
	clear := control
	clear.ExpectedRevision = 2
	clear.ModeEpoch++
	clear.OperationID = id(t)
	clear.Signature = ed25519.Sign(f.ownerKey, clear.SigningBytes())
	if _, err := f.s.PutControl(ctx, peer.Token, clear); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-owner clear: %v", err)
	}
	before, err := f.s.State(ctx, control.ProfileID, control.Generation, f.credential.Token)
	if err != nil || len(before.Heads) != 2 {
		t.Fatalf("copies after rejected clear: %+v %v", before, err)
	}
	receipt, err := f.s.PutControl(ctx, f.credential.Token, clear)
	if err != nil || receipt.Revision != 3 || receipt.Replayed {
		t.Fatalf("clear receipt: %+v %v", receipt, err)
	}
	for _, credential := range []Credential{f.credential, peer} {
		state, err := f.s.State(ctx, credential.ProfileID, credential.Generation, credential.Token)
		if err != nil || len(state.Heads) != 0 || state.KeyEpoch != 1 || state.ModeEpoch != 2 || state.CipherMode != "e2ee" {
			t.Fatalf("connection after clear: %+v %v", state, err)
		}
		if _, _, err := f.s.ReadEnvelope(ctx, credential.ProfileID, credential.Generation, credential.Token, credential.DeviceID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("old copy after clear: %v", err)
		}
	}
	stale := peerCopy
	stale.OperationID = id(t)
	stale.Signature = ed25519.Sign(peerKey, stale.SigningBytes())
	if _, err := f.s.Publish(ctx, peer.Token, stale); !errors.Is(err, ErrEpoch) {
		t.Fatalf("old epoch republished after clear: %v", err)
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, f.path, Limits{EnvelopeBytes: 1024, ProfileBytes: 1024, Devices: 8})
	if err != nil {
		t.Fatal(err)
	}
	f.s = reopened
	newCopy := peerCopy
	newCopy.OperationID = id(t)
	newCopy.ModeEpoch = clear.ModeEpoch
	newCopy.Signature = ed25519.Sign(peerKey, newCopy.SigningBytes())
	if _, err := f.s.Publish(ctx, peer.Token, newCopy); err != nil {
		t.Fatalf("same device/token after clear and restart: %v", err)
	}
	retry, err := f.s.PutControl(ctx, f.credential.Token, clear)
	if err != nil || !retry.Replayed || retry.Revision != receipt.Revision {
		t.Fatalf("clear retry: %+v %v", retry, err)
	}
	state, err := f.s.State(ctx, peer.ProfileID, peer.Generation, peer.Token)
	if err != nil || len(state.Heads) != 1 || state.Heads[0].DeviceID != peerID {
		t.Fatalf("new copy after clear retry: %+v %v", state, err)
	}
}
