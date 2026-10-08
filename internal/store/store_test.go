package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"nx-sync-server/internal/protocol"
)

type fixture struct {
	s                   *Store
	path                string
	credential          Credential
	deviceKey, ownerKey ed25519.PrivateKey
	control             protocol.Control
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, key
}
func id(t *testing.T) string {
	t.Helper()
	value, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "settings.sqlite")
	s, err := Create(ctx, path, Limits{EnvelopeBytes: 1024, ProfileBytes: 1024, Devices: 8})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{s: s, path: path}
	t.Cleanup(func() { _ = f.s.Close() })
	device, deviceKey := keypair(t)
	owner, ownerKey := keypair(t)
	f.deviceKey = deviceKey
	f.ownerKey = ownerKey
	f.credential, err = s.Bootstrap(ctx, device, owner)
	if err != nil {
		t.Fatal(err)
	}
	f.control = protocol.Control{ProfileID: f.credential.ProfileID, Generation: f.credential.Generation, OperationID: id(t), KeyEpoch: 1, ModeEpoch: 1, CipherMode: "e2ee", OwnerDeviceID: f.credential.DeviceID, OwnerPublicKey: owner, Members: []protocol.Member{{DeviceID: f.credential.DeviceID, PublicKey: device, Role: "writer"}}}
	f.control.Signature = ed25519.Sign(f.ownerKey, f.control.SigningBytes())
	if _, err = s.PutControl(ctx, f.credential.Token, f.control); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) envelope(t *testing.T) protocol.Envelope {
	t.Helper()
	e := protocol.Envelope{ProfileID: f.credential.ProfileID, DeviceID: f.credential.DeviceID, Generation: f.credential.Generation, OperationID: id(t), Sequence: 1, KeyEpoch: f.control.KeyEpoch, ModeEpoch: f.control.ModeEpoch, CipherMode: f.control.CipherMode, Payload: []byte("opaque client ciphertext")}
	e.Signature = ed25519.Sign(f.deviceKey, e.SigningBytes())
	return e
}

func (f *fixture) change(t *testing.T, c protocol.Control) (protocol.Receipt, error) {
	t.Helper()
	c.OperationID = id(t)
	c.Signature = ed25519.Sign(f.ownerKey, c.SigningBytes())
	return f.s.PutControl(context.Background(), f.credential.Token, c)
}

func TestPublishCASRetryAndTampering(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	e := f.envelope(t)
	r, err := f.s.Publish(ctx, f.credential.Token, e)
	if err != nil || r.Revision != 1 || r.Replayed {
		t.Fatalf("first receipt=%+v err=%v", r, err)
	}
	r, err = f.s.Publish(ctx, f.credential.Token, e)
	if err != nil || !r.Replayed || r.Revision != 1 {
		t.Fatalf("retry=%+v err=%v", r, err)
	}
	changed := e
	changed.Payload = []byte("tampered")
	if _, err = f.s.Publish(ctx, f.credential.Token, changed); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unsigned mutation: %v", err)
	}
	changed.Signature = ed25519.Sign(f.deviceKey, changed.SigningBytes())
	if _, err = f.s.Publish(ctx, f.credential.Token, changed); !errors.Is(err, ErrReplay) {
		t.Fatalf("operation-id reuse: %v", err)
	}
	changed.OperationID = id(t)
	changed.Signature = ed25519.Sign(f.deviceKey, changed.SigningBytes())
	if _, err = f.s.Publish(ctx, f.credential.Token, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale CAS: %v", err)
	}
	changed.ExpectedRevision = 1
	changed.Sequence = 2
	changed.Signature = ed25519.Sign(f.deviceKey, changed.SigningBytes())
	if r, err = f.s.Publish(ctx, f.credential.Token, changed); err != nil || r.Revision != 2 {
		t.Fatalf("next write: %+v %v", r, err)
	}
	heads, err := f.s.Heads(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token)
	if err != nil || len(heads) != 1 || heads[0].Revision != 2 {
		t.Fatalf("heads=%+v %v", heads, err)
	}
}

func TestConcurrentConnectionsCompareRevision(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	other, err := Open(ctx, f.path, f.s.limits)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	a, b := f.envelope(t), f.envelope(t)
	b.Payload = []byte("other update")
	b.Signature = ed25519.Sign(f.deviceKey, b.SigningBytes())
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i, s := range []*Store{f.s, other} {
		wg.Add(1)
		go func(i int, s *Store) {
			defer wg.Done()
			e := a
			if i == 1 {
				e = b
			}
			_, err := s.Publish(ctx, f.credential.Token, e)
			results <- err
		}(i, s)
	}
	wg.Wait()
	close(results)
	committed, conflicts := 0, 0
	for err := range results {
		if err == nil {
			committed++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected contention result: %v", err)
		}
	}
	if committed != 1 || conflicts != 1 {
		t.Fatalf("committed=%d conflicts=%d", committed, conflicts)
	}
}

func TestRevokeRotateAndNeverReAdd(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	pub, writer := keypair(t)
	second := id(t)
	c := f.control
	c.ExpectedRevision = 1
	c.Members = append(append([]protocol.Member(nil), c.Members...), protocol.Member{DeviceID: second, PublicKey: pub, Role: "writer"})
	if _, err := f.change(t, c); err != nil {
		t.Fatal(err)
	}
	credential, err := f.s.IssueCredential(ctx, c.ProfileID, second)
	if err != nil {
		t.Fatal(err)
	}
	e := f.envelope(t)
	e.DeviceID = second
	e.Signature = ed25519.Sign(writer, e.SigningBytes())
	if _, err = f.s.Publish(ctx, credential.Token, e); err != nil {
		t.Fatal(err)
	}
	revoked := c
	revoked.ExpectedRevision = 2
	revoked.Members = revoked.Members[:1]
	if _, err = f.change(t, revoked); !errors.Is(err, ErrEpoch) {
		t.Fatalf("revocation without key rotation: %v", err)
	}
	revoked.KeyEpoch = 2
	if _, err = f.change(t, revoked); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Publish(ctx, credential.Token, e); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked retry: %v", err)
	}
	if _, err = f.s.IssueCredential(ctx, c.ProfileID, second); !errors.Is(err, ErrClosed) {
		t.Fatalf("reissue revoked: %v", err)
	}
	c.ExpectedRevision = 3
	c.KeyEpoch = 2
	if _, err = f.change(t, c); !errors.Is(err, ErrForbidden) {
		t.Fatalf("resurrection with same ID: %v", err)
	}
	heads, err := f.s.Heads(ctx, c.ProfileID, c.Generation, f.credential.Token)
	if err != nil || len(heads) != 0 {
		t.Fatalf("revoked heads=%+v %v", heads, err)
	}
	if err = f.s.Close(); err != nil {
		t.Fatal(err)
	}
	f.s, err = Open(ctx, f.path, Limits{EnvelopeBytes: 1024, ProfileBytes: 1024, Devices: 8})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Publish(ctx, credential.Token, e); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked after restart: %v", err)
	}
}

func TestReaderAndOwnerTransfer(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	pub, writer := keypair(t)
	newOwner, newAuthority := keypair(t)
	second := id(t)
	c := f.control
	c.ExpectedRevision = 1
	c.Members = append(append([]protocol.Member(nil), c.Members...), protocol.Member{DeviceID: second, PublicKey: pub, Role: "reader"})
	if _, err := f.change(t, c); err != nil {
		t.Fatal(err)
	}
	cred, err := f.s.IssueCredential(ctx, c.ProfileID, second)
	if err != nil {
		t.Fatal(err)
	}
	e := f.envelope(t)
	e.DeviceID = second
	e.Signature = ed25519.Sign(writer, e.SigningBytes())
	if _, err = f.s.Publish(ctx, cred.Token, e); !errors.Is(err, ErrForbidden) {
		t.Fatalf("reader write: %v", err)
	}
	transfer := c
	transfer.ExpectedRevision = 2
	transfer.OwnerDeviceID = second
	transfer.OwnerPublicKey = newOwner
	transfer.Members = append([]protocol.Member(nil), c.Members...)
	transfer.Members[1].Role = "writer"
	if _, err = f.change(t, transfer); !errors.Is(err, ErrForbidden) {
		t.Fatalf("transfer without confirmation: %v", err)
	}
	transfer.OperationID = id(t)
	transfer.NewOwnerSignature = ed25519.Sign(newAuthority, transfer.ConfirmationBytes())
	transfer.Signature = ed25519.Sign(f.ownerKey, transfer.SigningBytes())
	if _, err = f.s.PutControl(ctx, f.credential.Token, transfer); err != nil {
		t.Fatal(err)
	}
	transfer.ExpectedRevision = 3
	if _, err = f.change(t, transfer); !errors.Is(err, ErrForbidden) {
		t.Fatalf("old authority: %v", err)
	}
	transfer.OperationID = id(t)
	transfer.NewOwnerSignature = nil
	transfer.Signature = ed25519.Sign(newAuthority, transfer.SigningBytes())
	if _, err = f.s.PutControl(ctx, cred.Token, transfer); err != nil {
		t.Fatalf("new owner: %v", err)
	}
}

func TestCloseReceiptCannotResurrect(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	e := f.envelope(t)
	if _, err := f.s.Publish(ctx, f.credential.Token, e); err != nil {
		t.Fatal(err)
	}
	c := f.control
	c.ExpectedRevision = 1
	c.KeyEpoch = 2
	c.Closed = true
	c.OperationID = id(t)
	c.Signature = ed25519.Sign(f.ownerKey, c.SigningBytes())
	if _, err := f.s.PutControl(ctx, f.credential.Token, c); err != nil {
		t.Fatal(err)
	}
	if r, err := f.s.PutControl(ctx, f.credential.Token, c); err != nil || !r.Replayed {
		t.Fatalf("closure retry: %+v %v", r, err)
	}
	if _, _, err := f.s.ReadControl(ctx, c.ProfileID, c.Generation, f.credential.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Publish(ctx, f.credential.Token, e); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed write: %v", err)
	}
	c.ExpectedRevision = 2
	c.Closed = false
	if _, err := f.change(t, c); !errors.Is(err, ErrClosed) {
		t.Fatalf("reopen: %v", err)
	}
}

func TestResetRecoveryPreservesNewGenerationWrites(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	old := f.credential.Generation
	target := id(t)
	identity, err := f.s.ResetGeneration(ctx, old, target)
	if err != nil || identity.Generation != target {
		t.Fatalf("reset=%+v %v", identity, err)
	}
	if _, err = f.s.Publish(ctx, f.credential.Token, f.envelope(t)); !errors.Is(err, ErrGeneration) {
		t.Fatalf("old credentials: %v", err)
	}
	pub, _ := keypair(t)
	newCredential, err := f.s.Bootstrap(ctx, pub, pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ResetGeneration(ctx, old, target); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Heads(ctx, newCredential.ProfileID, target, newCredential.Token); err != nil {
		t.Fatalf("recovery erased new profile: %v", err)
	}
	if _, err = f.s.ResetGeneration(ctx, old, id(t)); !errors.Is(err, ErrGeneration) {
		t.Fatalf("stale reset: %v", err)
	}
}

func TestStorageMissingFileQuotaAndBackup(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	e := f.envelope(t)
	e.Payload = make([]byte, 1024)
	e.Signature = ed25519.Sign(f.deviceKey, e.SigningBytes())
	f.s.limits.ProfileBytes = 32
	if _, err := f.s.Publish(ctx, f.credential.Token, e); !errors.Is(err, ErrQuota) {
		t.Fatalf("quota: %v", err)
	}
	backup := filepath.Join(t.TempDir(), "backup.sqlite")
	if err := f.s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	b, err := Open(ctx, backup, f.s.limits)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err = b.Heads(ctx, f.credential.ProfileID, f.credential.Generation, f.credential.Token); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.sqlite")
	if _, err = Open(ctx, missing, f.s.limits); err == nil {
		t.Fatal("startup created missing database")
	}
	if _, err = os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file created: %v", err)
	}
}
