package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"nx-sync-server/internal/protocol"
)

func adminCommand(t *testing.T, credential Credential, key ed25519.PrivateKey, action, target string, hash []byte) protocol.ServerCommand {
	t.Helper()
	c := protocol.ServerCommand{OperationID: id(t), Target: target, TicketHash: hash}
	c.Signature = ed25519.Sign(key, c.SigningBytes(action, credential.ProfileID, credential.Generation))
	return c
}

func guest(t *testing.T, s *Store) Credential {
	t.Helper()
	device, _ := keypair(t)
	owner, _ := keypair(t)
	c, err := s.Bootstrap(context.Background(), device, owner)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestServerOwnerBelongsToAccountAndPersists(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	member, memberKey := keypair(t)
	memberID := id(t)
	control := f.control
	control.ExpectedRevision = 1
	control.Members = append(control.Members, protocol.Member{DeviceID: memberID, PublicKey: member, Role: "writer"})
	if _, err := f.change(t, control); err != nil {
		t.Fatal(err)
	}
	second, err := f.s.IssueCredential(ctx, f.credential.ProfileID, memberID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []Credential{f.credential, second} {
		access, err := f.s.ServerAccess(ctx, c.ProfileID, c.Generation, c.Token)
		if err != nil || !access.Owner {
			t.Fatalf("owner device %+v: %v", access, err)
		}
	}
	control.ExpectedRevision = 2
	control.OperationID = id(t)
	control.Signature = ed25519.Sign(f.ownerKey, control.SigningBytes())
	if _, err = f.s.PutControl(ctx, second.Token, control); err != nil {
		t.Fatalf("account owner proof on second device: %v", err)
	}
	control.ExpectedRevision = 3
	control.ModeEpoch++
	control.OperationID = id(t)
	control.Signature = ed25519.Sign(f.ownerKey, control.SigningBytes())
	if _, err = f.s.PutControl(ctx, second.Token, control); err != nil {
		t.Fatalf("account-wide clear on second device: %v", err)
	}
	ticket, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(ticket))
	command := adminCommand(t, second, memberKey, "invite", "", hash[:])
	if _, err = f.s.InviteAccount(ctx, second.ProfileID, second.Generation, second.Token, command); err != nil {
		t.Fatal(err)
	}
	newAccount := guest(t, f.s)
	if err = f.s.Close(); err != nil {
		t.Fatal(err)
	}
	f.s, err = Open(ctx, f.path, f.s.limits)
	if err != nil {
		t.Fatal(err)
	}
	access, err := f.s.ServerAccess(ctx, newAccount.ProfileID, newAccount.Generation, newAccount.Token)
	if err != nil || access.Owner || !access.OwnerAssigned {
		t.Fatalf("second account after restart: %+v %v", access, err)
	}
	access, err = f.s.ServerAccess(ctx, second.ProfileID, second.Generation, second.Token)
	if err != nil || !access.Owner {
		t.Fatalf("owner after restart: %+v %v", access, err)
	}
}

func TestServerGuestCannotListInviteOrRevokeAndOwnerCannotRevokeSelf(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	g := guest(t, f.s)
	if _, err := f.s.ServerAccounts(ctx, g.ProfileID, g.Generation, g.Token, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("guest list: %v", err)
	}
	_, wrongKey := keypair(t)
	hash := sha256.Sum256([]byte("ticket"))
	c := adminCommand(t, g, wrongKey, "invite", "", hash[:])
	if _, err := f.s.InviteAccount(ctx, g.ProfileID, g.Generation, g.Token, c); !errors.Is(err, ErrForbidden) {
		t.Fatalf("guest invite: %v", err)
	}
	c = adminCommand(t, g, wrongKey, "revoke", f.credential.ProfileID, nil)
	if _, err := f.s.RevokeAccounts(ctx, g.ProfileID, g.Generation, g.Token, c); !errors.Is(err, ErrForbidden) {
		t.Fatalf("guest revoke: %v", err)
	}
	c = adminCommand(t, f.credential, f.deviceKey, "revoke", f.credential.ProfileID, nil)
	if _, err := f.s.RevokeAccounts(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token, c); !errors.Is(err, ErrForbidden) {
		t.Fatalf("owner self revoke: %v", err)
	}
}

func TestRevokeAccountPreservesOwnerAndNeedsFreshInvitation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	g := guest(t, f.s)
	if err := f.s.DescribeDevice(ctx, g.ProfileID, g.Generation, g.Token, DeviceDescription{AccountLabel: "Guest", Label: "Phone", Platform: "android", Version: "12.10.1"}); err != nil {
		t.Fatal(err)
	}
	page, err := f.s.ServerAccounts(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token, "")
	if err != nil || len(page.Accounts) != 2 {
		t.Fatalf("accounts: %+v %v", page, err)
	}
	c := adminCommand(t, f.credential, f.deviceKey, "revoke", g.ProfileID, nil)
	revoked, err := f.s.RevokeAccounts(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token, c)
	if err != nil || len(revoked) != 1 || revoked[0] != g.ProfileID {
		t.Fatalf("revoke: %v %v", revoked, err)
	}
	if _, err = f.s.State(ctx, g.ProfileID, g.Generation, g.Token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked read: %v", err)
	}
	if _, err = f.s.IssueCredential(ctx, g.ProfileID, g.DeviceID); !errors.Is(err, ErrClosed) {
		t.Fatalf("old device credential: %v", err)
	}
	if _, err = f.s.RevokeAccounts(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token, c); err != nil {
		t.Fatalf("lost response retry: %v", err)
	}
	if _, err = f.s.State(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token); err != nil {
		t.Fatalf("owner preserved: %v", err)
	}
	ticket, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(ticket))
	invite := adminCommand(t, f.credential, f.deviceKey, "invite", "", hash[:])
	if _, err = f.s.InviteAccount(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token, invite); err != nil {
		t.Fatal(err)
	}
	claim := bootstrapClaim(t, ticket, g.Generation)
	joined, err := f.s.ClaimBootstrap(ctx, claim)
	if err != nil || joined.ProfileID == g.ProfileID {
		t.Fatalf("fresh admission: %+v %v", joined, err)
	}
	if _, err = f.s.State(ctx, g.ProfileID, g.Generation, g.Token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("old access resurrected: %v", err)
	}
}

func TestConcurrentFirstBootstrapChoosesOneAccount(t *testing.T) {
	ctx := context.Background()
	s, err := Create(ctx, filepath.Join(t.TempDir(), "settings.sqlite"), Limits{EnvelopeBytes: 1024, ProfileBytes: 1024, Devices: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	claims := make([]protocol.BootstrapClaim, 2)
	for i := range claims {
		ticket, identity, _, err := s.NewBootstrapTicket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		claims[i] = bootstrapClaim(t, ticket, identity.Generation)
	}
	var wg sync.WaitGroup
	credentials := make([]Credential, 2)
	errorsFound := make([]error, 2)
	for i := range claims {
		wg.Add(1)
		go func(i int) { defer wg.Done(); credentials[i], errorsFound[i] = s.ClaimBootstrap(ctx, claims[i]) }(i)
	}
	wg.Wait()
	owners := 0
	for i, c := range credentials {
		if errorsFound[i] != nil {
			t.Fatal(errorsFound[i])
		}
		access, err := s.ServerAccess(ctx, c.ProfileID, c.Generation, c.Token)
		if err != nil {
			t.Fatal(err)
		}
		if access.Owner {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("owner accounts: %d", owners)
	}
}

func TestAmbiguousLegacyOwnershipRequiresTrustedMigration(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	g := guest(t, f.s)
	for _, table := range []string{"account_invitations", "device_info", "profile_access", "server_ownership"} {
		if _, err := f.s.db.ExecContext(ctx, "DROP TABLE "+table); err != nil {
			t.Fatal(err)
		}
	}
	limits := f.s.limits
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.s, err = Open(ctx, f.path, limits)
	if err != nil {
		t.Fatal(err)
	}
	access, err := f.s.ServerAccess(ctx, g.ProfileID, g.Generation, g.Token)
	if err != nil || access.Owner || !access.MigrationRequired {
		t.Fatalf("legacy role: %+v %v", access, err)
	}
	if err = f.s.AssignServerOwner(ctx, f.credential.ProfileID); err != nil {
		t.Fatal(err)
	}
	if err = f.s.AssignServerOwner(ctx, g.ProfileID); !errors.Is(err, ErrConflict) {
		t.Fatalf("replace existing owner: %v", err)
	}
	if _, err = f.s.State(ctx, g.ProfileID, g.Generation, g.Token); err != nil {
		t.Fatalf("migration kept guest connection: %v", err)
	}
}

func TestRevocationCannotResurrectPendingInvitation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	g := guest(t, f.s)
	ticket, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(ticket))
	invite := adminCommand(t, f.credential, f.deviceKey, "invite", "", hash[:])
	if _, err = f.s.InviteAccount(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token, invite); err != nil {
		t.Fatal(err)
	}
	revoke := adminCommand(t, f.credential, f.deviceKey, "revoke", g.ProfileID, nil)
	if _, err = f.s.RevokeAccounts(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token, revoke); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.InviteAccount(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token, invite); !errors.Is(err, ErrInvitationExpired) {
		t.Fatalf("old invitation retried: %v", err)
	}
	claim := bootstrapClaim(t, ticket, f.credential.Generation)
	if _, err = f.s.ClaimBootstrap(ctx, claim); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cancelled invitation: %v", err)
	}
}

func TestServerAccountsPaginationKeepsOwnerFirstWithoutDuplicates(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for i := 0; i < 55; i++ {
		guest(t, f.s)
	}
	seen := make(map[string]bool)
	after := ""
	for {
		page, err := f.s.ServerAccounts(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token, after)
		if err != nil {
			t.Fatal(err)
		}
		if after == "" && (len(page.Accounts) == 0 || !page.Accounts[0].Owner) {
			t.Fatal("owner must be first")
		}
		if len(page.Accounts) > 50 {
			t.Fatal("page exceeds limit")
		}
		for _, account := range page.Accounts {
			if seen[account.ProfileID] {
				t.Fatal("duplicate account")
			}
			seen[account.ProfileID] = true
		}
		if page.Next == "" {
			break
		}
		after = page.Next
	}
	if len(seen) != 56 {
		t.Fatalf("accounts: %d", len(seen))
	}
}

func TestTrustedOwnerRecoveryPreservesOtherProfiles(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	g := guest(t, f.s)
	if err := f.s.RecoverServerOwner(ctx, g.ProfileID); err != nil {
		t.Fatal(err)
	}
	access, err := f.s.ServerAccess(ctx, g.ProfileID, g.Generation, g.Token)
	if err != nil || !access.Owner {
		t.Fatalf("recovered owner: %+v %v", access, err)
	}
	access, err = f.s.ServerAccess(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token)
	if err != nil || access.Owner {
		t.Fatalf("previous account: %+v %v", access, err)
	}
	if _, err = f.s.State(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token); err != nil {
		t.Fatalf("preserved original profile: %v", err)
	}
}
