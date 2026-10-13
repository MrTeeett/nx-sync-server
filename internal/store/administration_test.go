package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"nx-sync-server/internal/protocol"
)

func administrationPacket(t *testing.T, f *fixture, revision uint64) protocol.Administration {
	t.Helper()
	a := protocol.Administration{ProfileID: f.credential.ProfileID, Generation: f.credential.Generation,
		DeviceID: f.credential.DeviceID, OperationID: id(t), ExpectedRevision: revision, KeyEpoch: 1,
		Payload: bytes.Repeat([]byte{0xa7}, 64)}
	a.Signature = ed25519.Sign(f.deviceKey, a.SigningBytes())
	return a
}

func TestAdministrationIsOpaqueOwnerAccountCAS(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.s.limits.ProfileBytes = 16384
	g := guest(t, f.s)
	if _, err := f.s.Administration(ctx, g.ProfileID, g.Generation, g.Token); !errors.Is(err, ErrForbidden) {
		t.Fatalf("guest read: %v", err)
	}
	a := administrationPacket(t, f, 0)
	if _, err := f.s.PutAdministration(ctx, g.Token, a); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-profile write: %v", err)
	}
	state, err := f.s.Administration(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token)
	if err != nil || state.Revision != 0 || state.Packet != nil {
		t.Fatalf("empty state: %+v %v", state, err)
	}
	r, err := f.s.PutAdministration(ctx, f.credential.Token, a)
	if err != nil || r.Revision != 1 || r.Replayed {
		t.Fatalf("first receipt: %+v %v", r, err)
	}
	r, err = f.s.PutAdministration(ctx, f.credential.Token, a)
	if err != nil || !r.Replayed || r.Revision != 1 {
		t.Fatalf("retry receipt: %+v %v", r, err)
	}
	state, err = f.s.Administration(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token)
	if err != nil || state.Packet == nil || !bytes.Equal(a.Payload, state.Packet.Payload) {
		t.Fatalf("opaque read: %+v %v", state, err)
	}
	tampered := a
	tampered.Payload = bytes.Repeat([]byte{1}, 64)
	if _, err = f.s.PutAdministration(ctx, f.credential.Token, tampered); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tamper: %v", err)
	}
	stale := administrationPacket(t, f, 0)
	if _, err = f.s.PutAdministration(ctx, f.credential.Token, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("CAS: %v", err)
	}
	second := administrationPacket(t, f, 1)
	second.Payload = bytes.Repeat([]byte{2}, 64)
	second.Signature = ed25519.Sign(f.deviceKey, second.SigningBytes())
	if _, err = f.s.PutAdministration(ctx, f.credential.Token, second); err != nil {
		t.Fatalf("replacement: %v", err)
	}
	member, memberKey := keypair(t)
	memberID := id(t)
	control := f.control
	control.ExpectedRevision = 1
	control.Members = append(control.Members, protocol.Member{DeviceID: memberID, PublicKey: member, Role: "writer"})
	if _, err = f.change(t, control); err != nil {
		t.Fatal(err)
	}
	c, err := f.s.IssueCredential(ctx, f.credential.ProfileID, memberID)
	if err != nil {
		t.Fatal(err)
	}
	state, err = f.s.Administration(ctx, c.ProfileID, c.Generation, c.Token)
	if err != nil || state.Revision != 2 {
		t.Fatalf("other owner device read: %+v %v", state, err)
	}
	third := administrationPacket(t, f, 2)
	third.DeviceID = memberID
	third.Signature = ed25519.Sign(memberKey, third.SigningBytes())
	if _, err = f.s.PutAdministration(ctx, c.Token, third); err != nil {
		t.Fatalf("other owner device write: %v", err)
	}
}

func TestAdministrationCountsAgainstProfileQuota(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := administrationPacket(t, f, 0)
	if _, err := f.s.PutAdministration(ctx, f.credential.Token, a); err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	used, err := profileUsage(ctx, tx, f.credential.ProfileID)
	tx.Rollback()
	if err != nil || used < 64 {
		t.Fatalf("usage: %d %v", used, err)
	}
	f.s.limits.ProfileBytes = used
	if _, err = f.s.Publish(ctx, f.credential.Token, f.envelope(t)); !errors.Is(err, ErrQuota) {
		t.Fatalf("envelope bypass: %v", err)
	}
	second := administrationPacket(t, f, 1)
	if _, err = f.s.PutAdministration(ctx, f.credential.Token, second); err != nil {
		t.Fatalf("same-size replacement should fit: %v", err)
	}
}
