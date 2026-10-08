package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"nx-sync-server/internal/protocol"
	"os"
)

func (s *Store) PutControl(ctx context.Context, token string, c protocol.Control) (protocol.Receipt, error) {
	if err := c.Validate(s.limits.Devices); err != nil {
		return protocol.Receipt{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.Receipt{}, err
	}
	defer tx.Rollback()
	a, authErr := authenticate(ctx, tx, c.ProfileID, c.Generation, token)
	if authErr != nil && !errors.Is(authErr, ErrClosed) {
		return protocol.Receipt{}, authErr
	}
	if a.id != a.ownerID || !ed25519.Verify(a.ownerKey, c.SigningBytes(), c.Signature) {
		return protocol.Receipt{}, ErrForbidden
	}
	digest := sha256.Sum256(c.SigningBytes())
	if r, found, err := dedup(ctx, tx, c.ProfileID, a.id, "control", c.OperationID, digest[:]); found || err != nil {
		return r, err
	}
	if authErr != nil {
		return protocol.Receipt{}, authErr
	}
	if c.ExpectedRevision != a.controlRevision {
		return protocol.Receipt{}, ErrConflict
	}
	if c.KeyEpoch < a.keyEpoch || c.ModeEpoch < a.modeEpoch || (c.CipherMode != a.mode && c.ModeEpoch <= a.modeEpoch) {
		return protocol.Receipt{}, ErrEpoch
	}
	ownerChanged := c.OwnerDeviceID != a.ownerID || !bytesEqual(c.OwnerPublicKey, a.ownerKey)
	if ownerChanged && (c.Closed || !ed25519.Verify(c.OwnerPublicKey, c.ConfirmationBytes(), c.NewOwnerSignature)) {
		return protocol.Receipt{}, ErrForbidden
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,public_key,active FROM devices WHERE profile=?", c.ProfileID)
	if err != nil {
		return protocol.Receipt{}, err
	}
	type device struct {
		key    []byte
		active bool
	}
	old := map[string]device{}
	for rows.Next() {
		var id string
		var key []byte
		var active int
		if err = rows.Scan(&id, &key, &active); err != nil {
			break
		}
		old[id] = device{key: key, active: active == 1}
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return protocol.Receipt{}, err
	}
	newMembers := map[string]bool{}
	newCount := 0
	for _, member := range c.Members {
		newMembers[member.DeviceID] = true
		if prior, exists := old[member.DeviceID]; exists && (!prior.active || !bytesEqual(prior.key, member.PublicKey)) {
			return protocol.Receipt{}, ErrForbidden
		}
		if _, exists := old[member.DeviceID]; !exists {
			newCount++
		}
	}
	if len(old)+newCount > 1024 {
		return protocol.Receipt{}, ErrQuota
	}
	removed := false
	for id, d := range old {
		if d.active && !newMembers[id] {
			removed = true
		}
	}
	if (removed || c.Closed) && a.mode == "e2ee" && c.KeyEpoch <= a.keyEpoch {
		return protocol.Receipt{}, ErrEpoch
	}
	for id := range old {
		if !newMembers[id] || c.Closed {
			// Retain only the owner's hash for read-only closure status/idempotent receipt.
			if c.Closed && id == a.ownerID {
				_, err = tx.ExecContext(ctx, "UPDATE devices SET active=0 WHERE profile=? AND id=?", c.ProfileID, id)
			} else {
				_, err = tx.ExecContext(ctx, "UPDATE devices SET active=0,token_hash=NULL WHERE profile=? AND id=?", c.ProfileID, id)
			}
			if err != nil {
				return protocol.Receipt{}, err
			}
		}
	}
	if !c.Closed {
		for _, member := range c.Members {
			_, err = tx.ExecContext(ctx, `INSERT INTO devices(profile,id,public_key,role) VALUES(?,?,?,?) ON CONFLICT(profile,id) DO UPDATE SET role=excluded.role`, c.ProfileID, member.DeviceID, member.PublicKey, member.Role)
			if err != nil {
				return protocol.Receipt{}, err
			}
		}
	}
	data, err := json.Marshal(c)
	if err != nil {
		return protocol.Receipt{}, err
	}
	revision := a.controlRevision + 1
	_, err = tx.ExecContext(ctx, "UPDATE profiles SET owner_id=?,owner_key=?,closed=?,revision=?,key_epoch=?,mode_epoch=?,mode=?,control=? WHERE id=?", c.OwnerDeviceID, c.OwnerPublicKey, c.Closed, revision, c.KeyEpoch, c.ModeEpoch, c.CipherMode, data, c.ProfileID)
	if err != nil {
		return protocol.Receipt{}, err
	}
	// Removing a writer also removes its committed slot. Old epochs are never listed.
	_, err = tx.ExecContext(ctx, `DELETE FROM envelopes WHERE profile=? AND (device NOT IN (SELECT id FROM devices WHERE profile=? AND active=1) OR key_epoch<>? OR mode_epoch<>?)`, c.ProfileID, c.ProfileID, c.KeyEpoch, c.ModeEpoch)
	if err == nil {
		err = record(ctx, tx, c.ProfileID, a.id, "control", c.OperationID, digest[:], revision)
	}
	if err == nil {
		err = tx.Commit()
	}
	return protocol.Receipt{Revision: revision, OperationID: c.OperationID}, err
}

// IssueCredential is SSH/local administration for an already signed member.
// Native invitation enrollment will use the same durable membership checks.
func (s *Store) IssueCredential(ctx context.Context, profile, device string) (Credential, error) {
	if !protocol.ValidID(profile) || !protocol.ValidID(device) {
		return Credential{}, ErrNotFound
	}
	token, hash, err := newToken()
	if err != nil {
		return Credential{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Credential{}, err
	}
	defer tx.Rollback()
	var generation string
	if err = tx.QueryRowContext(ctx, "SELECT generation FROM metadata WHERE id=1").Scan(&generation); err != nil {
		return Credential{}, err
	}
	var active, closed int
	err = tx.QueryRowContext(ctx, "SELECT d.active,p.closed FROM devices d JOIN profiles p ON p.id=d.profile WHERE d.profile=? AND d.id=?", profile, device).Scan(&active, &closed)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	if err != nil {
		return Credential{}, err
	}
	if active != 1 || closed != 0 {
		return Credential{}, ErrClosed
	}
	if _, err = tx.ExecContext(ctx, "UPDATE devices SET token_hash=? WHERE profile=? AND id=?", hash, profile, device); err != nil {
		return Credential{}, err
	}
	if err = tx.Commit(); err != nil {
		return Credential{}, err
	}
	return Credential{ProfileID: profile, DeviceID: device, Generation: generation, Token: token}, nil
}

func (s *Store) ReadControl(ctx context.Context, profile, generation, token string) ([]byte, uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	a, err := authenticate(ctx, tx, profile, generation, token)
	if err != nil && !(errors.Is(err, ErrClosed) && a.id == a.ownerID) {
		return nil, 0, err
	}
	var data []byte
	var revision uint64
	err = tx.QueryRowContext(ctx, "SELECT control,revision FROM profiles WHERE id=?", profile).Scan(&data, &revision)
	if err == nil && len(data) == 0 {
		err = ErrNotFound
	}
	return data, revision, err
}

func (s *Store) Heads(ctx context.Context, profile, generation, token string) ([]protocol.Head, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, err := authenticate(ctx, tx, profile, generation, token)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT device,revision,sequence,hash FROM envelopes WHERE profile=? AND key_epoch=? AND mode_epoch=? ORDER BY device", profile, a.keyEpoch, a.modeEpoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	heads := make([]protocol.Head, 0)
	for rows.Next() {
		var head protocol.Head
		if err = rows.Scan(&head.DeviceID, &head.Revision, &head.Sequence, &head.Hash); err != nil {
			return nil, err
		}
		heads = append(heads, head)
	}
	return heads, rows.Err()
}

func (s *Store) ReadEnvelope(ctx context.Context, profile, generation, token, device string) ([]byte, uint64, error) {
	if !protocol.ValidID(device) {
		return nil, 0, ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	a, err := authenticate(ctx, tx, profile, generation, token)
	if err != nil {
		return nil, 0, err
	}
	var data []byte
	var revision uint64
	err = tx.QueryRowContext(ctx, "SELECT data,revision FROM envelopes WHERE profile=? AND device=? AND key_epoch=? AND mode_epoch=?", profile, device, a.keyEpoch, a.modeEpoch).Scan(&data, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return data, revision, err
}

// Reset must be invoked while the system service/socket is stopped and locked.
// The transaction preserves lifecycle metadata and replaces the generation.
func (s *Store) Reset(ctx context.Context) (Identity, error) {
	generation, err := protocol.NewID()
	if err != nil {
		return Identity{}, err
	}
	id, err := s.Identity(ctx)
	if err != nil {
		return Identity{}, err
	}
	return s.ResetGeneration(ctx, id.Generation, generation)
}

// ResetGeneration makes recovery idempotent: a completed reset is never
// repeated over writes that arrived after the new generation became active.
func (s *Store) ResetGeneration(ctx context.Context, expected, generation string) (Identity, error) {
	if !protocol.ValidID(expected) || !protocol.ValidID(generation) || expected == generation {
		return Identity{}, ErrGeneration
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Identity{}, err
	}
	defer tx.Rollback()
	var current string
	if err = tx.QueryRowContext(ctx, "SELECT generation FROM metadata WHERE id=1").Scan(&current); err != nil {
		return Identity{}, err
	}
	if current == generation {
		_ = tx.Rollback()
		return s.Identity(ctx)
	}
	if current != expected {
		return Identity{}, ErrGeneration
	}
	for _, table := range []string{"envelopes", "operations", "devices", "profiles"} {
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return Identity{}, err
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE metadata SET generation=? WHERE id=1", generation); err != nil {
		return Identity{}, err
	}
	if err = tx.Commit(); err != nil {
		return Identity{}, err
	}
	// VACUUM cannot run inside the transaction. Logical reset is already durable.
	if _, err = s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return Identity{}, err
	}
	if _, err = s.db.ExecContext(ctx, "VACUUM"); err != nil {
		return Identity{}, err
	}
	return s.Identity(ctx)
}

// Backup creates a consistent schema-1 snapshot. Management keeps this in a
// root-only directory and never restores it over a database with newer writes.
func (s *Store) Backup(ctx context.Context, path string) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("backup path already exists or cannot be inspected")
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
