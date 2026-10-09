package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"nx-sync-server/internal/protocol"
)

func bootstrapClaim(t *testing.T, ticket, generation string) protocol.BootstrapClaim {
	t.Helper()
	device, deviceSeed := keypair(t)
	owner, ownerSeed := keypair(t)
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := id(t)
	control := protocol.Control{ProfileID: id(t), Generation: generation, OperationID: id(t), KeyEpoch: 1, ModeEpoch: 1, CipherMode: "e2ee", OwnerDeviceID: deviceID, OwnerPublicKey: owner, Members: []protocol.Member{{DeviceID: deviceID, PublicKey: device, Role: "writer"}}}
	control.Signature = ed25519.Sign(ownerSeed, control.SigningBytes())
	claim := protocol.BootstrapClaim{Ticket: ticket, Token: token, Control: control}
	claim.Signature = ed25519.Sign(deviceSeed, claim.SigningBytes())
	return claim
}

func TestBootstrapTicketOneUseRetryAndReset(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	ticket, identity, expires, err := f.s.NewBootstrapTicket(ctx)
	if err != nil || expires == 0 {
		t.Fatal(err)
	}
	claim := bootstrapClaim(t, ticket, identity.Generation)
	credential, err := f.s.ClaimBootstrap(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.s.ClaimBootstrap(ctx, claim)
	if err != nil || retry != credential {
		t.Fatalf("lost response retry: %v", err)
	}
	state, err := f.s.State(ctx, credential.ProfileID, credential.Generation, credential.Token)
	if err != nil || state.ControlRevision != 1 || len(state.Heads) != 0 {
		t.Fatalf("initial signed membership: %+v %v", state, err)
	}
	other := bootstrapClaim(t, ticket, identity.Generation)
	if _, err = f.s.ClaimBootstrap(ctx, other); !errors.Is(err, ErrReplay) {
		t.Fatalf("ticket reuse: %v", err)
	}
	if _, err = f.s.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ClaimBootstrap(ctx, claim); !errors.Is(err, ErrGeneration) {
		t.Fatalf("reset ticket: %v", err)
	}
}

func TestExpiredBootstrapAndMissingProof(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	ticket, identity, _, err := f.s.NewBootstrapTicket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	claim := bootstrapClaim(t, ticket, identity.Generation)
	claim.Signature[0] ^= 1
	if _, err = f.s.ClaimBootstrap(ctx, claim); !errors.Is(err, ErrForbidden) {
		t.Fatalf("missing device proof: %v", err)
	}
	claim = bootstrapClaim(t, ticket, identity.Generation)
	if _, err = f.s.db.ExecContext(ctx, "UPDATE bootstrap_tickets SET expires=0"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ClaimBootstrap(ctx, claim); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired ticket: %v", err)
	}
}

func TestInvitationBindsApprovedDeviceAndSurvivesLostResponse(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	pub, key := keypair(t)
	memberID := id(t)
	control := f.control
	control.ExpectedRevision = 1
	control.Members = append(control.Members, protocol.Member{DeviceID: memberID, PublicKey: pub, Role: "writer"})
	if _, err := f.change(t, control); err != nil {
		t.Fatal(err)
	}
	ticket, hash, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	i := protocol.Invitation{ProfileID: f.credential.ProfileID, Generation: f.credential.Generation, OperationID: id(t), ExpectedRevision: 2, DeviceID: memberID, TicketHash: hash, Box: make([]byte, 80)}
	i.Signature = ed25519.Sign(f.ownerKey, i.SigningBytes())
	expires, err := f.s.Invite(ctx, f.credential.Token, i)
	if err != nil {
		t.Fatal(err)
	}
	if repeated, err := f.s.Invite(ctx, f.credential.Token, i); err != nil || repeated != expires {
		t.Fatalf("invitation retry: %v", err)
	}
	token, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	claim := protocol.InvitationClaim{ProfileID: i.ProfileID, Generation: i.Generation, DeviceID: memberID, OperationID: id(t), Ticket: ticket, Token: token}
	_, wrongKey := keypair(t)
	claim.Signature = ed25519.Sign(wrongKey, claim.SigningBytes())
	if _, err = f.s.ClaimInvitation(ctx, claim); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unapproved key: %v", err)
	}
	claim.Signature = ed25519.Sign(key, claim.SigningBytes())
	joined, err := f.s.ClaimInvitation(ctx, claim)
	if err != nil || joined.Credential.Token != token || len(joined.Box) != 80 {
		t.Fatalf("join: %v", err)
	}
	if retry, err := f.s.ClaimInvitation(ctx, claim); err != nil || retry.Credential != joined.Credential {
		t.Fatalf("join retry: %v", err)
	}
	oldToken := claim.Token
	claim.Token, _, err = newToken()
	if err != nil {
		t.Fatal(err)
	}
	claim.Signature = ed25519.Sign(key, claim.SigningBytes())
	if _, err = f.s.ClaimInvitation(ctx, claim); !errors.Is(err, ErrReplay) {
		t.Fatalf("reuse with new token: %v", err)
	}
	claim.Token = oldToken
	claim.Signature = ed25519.Sign(key, claim.SigningBytes())
	if _, err = f.s.State(ctx, i.ProfileID, i.Generation, token); err != nil {
		t.Fatalf("joined access: %v", err)
	}
	control = f.control
	control.ExpectedRevision = 2
	control.KeyEpoch = 2
	if _, err = f.change(t, control); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ClaimInvitation(ctx, claim); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked invitation: %v", err)
	}
}

func TestEnrollmentMigrationRetainsExistingProfile(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, query := range []string{"DROP TABLE invitations", "DROP TABLE bootstrap_tickets", "UPDATE metadata SET schema_version=1"} {
		if _, err := f.s.db.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	limits := f.s.limits
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, f.path, limits)
	if err != nil {
		t.Fatal(err)
	}
	f.s = s
	if _, err = s.State(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token); err != nil {
		t.Fatal(err)
	}
	ticket, _, _, err := s.NewBootstrapTicket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(ticket))
	var saved []byte
	if err = s.db.QueryRowContext(ctx, "SELECT hash FROM bootstrap_tickets").Scan(&saved); err != nil || !bytesEqual(saved, hash[:]) {
		t.Fatalf("hashed ticket: %v", err)
	}
}
