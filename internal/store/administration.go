package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"

	"nx-sync-server/internal/protocol"
)

// AdministrationState holds the current revision and its opaque encrypted packet.
type AdministrationState struct {
	Revision uint64                   `json:"revision,string"`
	Packet   *protocol.Administration `json:"packet,omitempty"`
}

// Administration returns ciphertext only to active devices of the server owner.
func (s *Store) Administration(ctx context.Context, profile, generation, token string) (AdministrationState, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AdministrationState{}, err
	}
	defer tx.Rollback()
	if _, err = serverOwner(ctx, tx, profile, generation, token); err != nil {
		return AdministrationState{}, err
	}
	var data []byte
	var state AdministrationState
	err = tx.QueryRowContext(ctx, "SELECT revision,data FROM server_administration WHERE profile=?", profile).Scan(&state.Revision, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	state.Packet = &protocol.Administration{}
	return state, json.Unmarshal(data, state.Packet)
}

// PutAdministration verifies an owner device signature and commits a bounded CAS write.
func (s *Store) PutAdministration(ctx context.Context, token string, packet protocol.Administration) (protocol.Receipt, error) {
	if !protocol.ValidID(packet.ProfileID) || !protocol.ValidID(packet.Generation) || !protocol.ValidID(packet.DeviceID) || !protocol.ValidID(packet.OperationID) || len(packet.Payload) < 40 || len(packet.Payload) > 24576 {
		return protocol.Receipt{}, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.Receipt{}, err
	}
	defer tx.Rollback()
	a, err := serverOwner(ctx, tx, packet.ProfileID, packet.Generation, token)
	if err != nil {
		return protocol.Receipt{}, err
	}
	if a.id != packet.DeviceID || !ed25519.Verify(a.key, packet.SigningBytes(), packet.Signature) {
		return protocol.Receipt{}, ErrForbidden
	}
	digest := sha256.Sum256(packet.SigningBytes())
	if receipt, found, err := dedup(ctx, tx, packet.ProfileID, a.id, "administration", packet.OperationID, digest[:]); found || err != nil {
		return receipt, err
	}
	if packet.KeyEpoch != a.keyEpoch {
		return protocol.Receipt{}, ErrEpoch
	}
	var revision uint64
	var previousSize int64
	err = tx.QueryRowContext(ctx, "SELECT revision,length(data) FROM server_administration WHERE profile=?", packet.ProfileID).Scan(&revision, &previousSize)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return protocol.Receipt{}, err
	}
	if packet.ExpectedRevision != revision || revision >= 1<<63-1 {
		return protocol.Receipt{}, ErrConflict
	}
	data, err := json.Marshal(packet)
	if err != nil {
		return protocol.Receipt{}, err
	}
	used, err := profileUsage(ctx, tx, packet.ProfileID)
	if err != nil {
		return protocol.Receipt{}, err
	}
	if used-previousSize+int64(len(data)) > s.limits.ProfileBytes {
		return protocol.Receipt{}, ErrQuota
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO server_administration(profile,revision,data) VALUES(?,?,?) ON CONFLICT(profile) DO UPDATE SET revision=excluded.revision,data=excluded.data`, packet.ProfileID, revision+1, data); err != nil {
		return protocol.Receipt{}, err
	}
	if err = record(ctx, tx, packet.ProfileID, a.id, "administration", packet.OperationID, digest[:], revision+1); err != nil {
		return protocol.Receipt{}, err
	}
	return protocol.Receipt{Revision: revision + 1, OperationID: packet.OperationID}, tx.Commit()
}
