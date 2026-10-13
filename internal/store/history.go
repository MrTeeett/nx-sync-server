package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"

	"nx-sync-server/internal/protocol"
)

const historySchema = `
CREATE TABLE IF NOT EXISTS history_snapshots (
 profile TEXT NOT NULL, chat TEXT NOT NULL, device TEXT NOT NULL, phase INTEGER NOT NULL CHECK(phase IN (0,1)),
 operation TEXT NOT NULL, revision INTEGER NOT NULL, sequence INTEGER NOT NULL,
 key_epoch INTEGER NOT NULL, mode_epoch INTEGER NOT NULL, size INTEGER NOT NULL, hash TEXT NOT NULL, data BLOB NOT NULL,
 PRIMARY KEY(profile,chat,device,phase), UNIQUE(profile,chat,device,operation),
 FOREIGN KEY(profile,device) REFERENCES devices(profile,id));
CREATE TABLE IF NOT EXISTS history_parts (
 profile TEXT NOT NULL, chat TEXT NOT NULL, device TEXT NOT NULL, phase INTEGER NOT NULL,
 part INTEGER NOT NULL, data BLOB NOT NULL,
 PRIMARY KEY(profile,chat,device,phase,part),
 FOREIGN KEY(profile,chat,device,phase) REFERENCES history_snapshots(profile,chat,device,phase) ON DELETE CASCADE ON UPDATE CASCADE);
`

func (s *Store) migrateHistory(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var present int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM pragma_table_info('profiles') WHERE name='history_revision'").Scan(&present); err != nil {
		return err
	}
	if present == 0 {
		if _, err = tx.ExecContext(ctx, "ALTER TABLE profiles ADD COLUMN history_revision INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, historySchema); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE metadata SET schema_version=3 WHERE id=1"); err != nil {
		return err
	}
	return tx.Commit()
}

// Replacing a snapshot reserves the larger of the old and staged copies.
// Physical payload storage is bounded by twice the logical profile quota.
func profileUsage(ctx context.Context, tx *sql.Tx, profile string) (int64, error) {
	var used int64
	err := tx.QueryRowContext(ctx, `SELECT
 (SELECT COALESCE(SUM(size),0) FROM envelopes WHERE profile=?)+
 (SELECT COALESCE(SUM(length(box)),0) FROM invitations WHERE profile=?)+
 (SELECT COALESCE(SUM(size),0) FROM (SELECT MAX(size) AS size FROM history_snapshots WHERE profile=? GROUP BY chat,device))`, profile, profile, profile).Scan(&used)
	return used, err
}

func historyActor(ctx context.Context, tx *sql.Tx, token string, m protocol.HistoryManifest) (actor, error) {
	a, err := authenticate(ctx, tx, m.ProfileID, m.Generation, token)
	if err != nil {
		return a, err
	}
	if a.controlRevision == 0 || a.id != m.DeviceID || a.role != "writer" ||
		!ed25519.Verify(a.key, m.SigningBytes(), m.Signature) {
		return a, ErrForbidden
	}
	return a, nil
}

func historyEpoch(a actor, m protocol.HistoryManifest) error {
	if a.mode != "e2ee" || m.KeyEpoch != a.keyEpoch || m.ModeEpoch != a.modeEpoch {
		return ErrEpoch
	}
	return nil
}

func historyCurrent(ctx context.Context, tx *sql.Tx, m protocol.HistoryManifest) (uint64, uint64, error) {
	var revision, sequence uint64
	err := tx.QueryRowContext(ctx, "SELECT revision,sequence FROM history_snapshots WHERE profile=? AND chat=? AND device=? AND phase=0", m.ProfileID, m.ChatID, m.DeviceID).Scan(&revision, &sequence)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return revision, sequence, err
}

func (s *Store) BeginHistory(ctx context.Context, token string, m protocol.HistoryManifest) (protocol.Receipt, error) {
	if err := m.Validate(s.limits.EnvelopeBytes); err != nil {
		return protocol.Receipt{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.Receipt{}, err
	}
	defer tx.Rollback()
	a, err := historyActor(ctx, tx, token, m)
	if err != nil {
		return protocol.Receipt{}, err
	}
	digest := sha256.Sum256(m.SigningBytes())
	if r, found, err := dedup(ctx, tx, m.ProfileID, a.id, "history:"+m.ChatID, m.OperationID, digest[:]); found || err != nil {
		return r, err
	}
	if err = historyEpoch(a, m); err != nil {
		return protocol.Receipt{}, err
	}
	revision, sequence, err := historyCurrent(ctx, tx, m)
	if err != nil {
		return protocol.Receipt{}, err
	}
	if revision != m.ExpectedRevision || sequence >= m.Sequence {
		return protocol.Receipt{}, ErrConflict
	}
	var priorHash string
	err = tx.QueryRowContext(ctx, "SELECT hash FROM history_snapshots WHERE profile=? AND chat=? AND device=? AND phase=1 AND operation=?", m.ProfileID, m.ChatID, m.DeviceID, m.OperationID).Scan(&priorHash)
	if err == nil {
		if priorHash != hex.EncodeToString(digest[:]) {
			return protocol.Receipt{}, ErrReplay
		}
		return protocol.Receipt{Revision: revision, OperationID: m.OperationID}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return protocol.Receipt{}, err
	}
	// One incomplete upload per device/chat; an abandoned stage is replaceable.
	if _, err = tx.ExecContext(ctx, "DELETE FROM history_snapshots WHERE profile=? AND chat=? AND device=? AND phase=1", m.ProfileID, m.ChatID, m.DeviceID); err != nil {
		return protocol.Receipt{}, err
	}
	var slots int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM (SELECT chat,device FROM history_snapshots WHERE profile=? GROUP BY chat,device)", m.ProfileID).Scan(&slots); err != nil {
		return protocol.Receipt{}, err
	}
	if revision == 0 && slots >= 4096 {
		return protocol.Receipt{}, ErrQuota
	}
	data, err := json.Marshal(m)
	if err != nil {
		return protocol.Receipt{}, err
	}
	size := int64(len(data))
	for _, part := range m.Parts {
		size += int64(part.Size)
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO history_snapshots VALUES(?,?,?,1,?,?,?,?,?,?,?,?)", m.ProfileID, m.ChatID, m.DeviceID, m.OperationID, revision+1, m.Sequence, m.KeyEpoch, m.ModeEpoch, size, hex.EncodeToString(digest[:]), data)
	if err != nil {
		return protocol.Receipt{}, err
	}
	used, err := profileUsage(ctx, tx, m.ProfileID)
	if err != nil {
		return protocol.Receipt{}, err
	}
	if used > s.limits.ProfileBytes {
		return protocol.Receipt{}, ErrQuota
	}
	return protocol.Receipt{Revision: revision, OperationID: m.OperationID}, tx.Commit()
}

func loadHistory(ctx context.Context, tx *sql.Tx, profile, chat, device, operation string, committed bool) (protocol.HistoryManifest, int, error) {
	var m protocol.HistoryManifest
	var data []byte
	var phase int
	query := "SELECT data,phase FROM history_snapshots WHERE profile=? AND chat=? AND device=? AND operation=?"
	if committed {
		query += " AND phase=0"
	}
	err := tx.QueryRowContext(ctx, query, profile, chat, device, operation).Scan(&data, &phase)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal(data, &m)
	}
	return m, phase, err
}

func (s *Store) PutHistoryPart(ctx context.Context, profile, generation, token, chat, device, operation string, index int, data []byte) error {
	if len(data) < 40 || int64(len(data)) > s.limits.EnvelopeBytes {
		return ErrQuota
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	a, err := authenticate(ctx, tx, profile, generation, token)
	if err != nil {
		return err
	}
	if a.id != device || a.role != "writer" {
		return ErrForbidden
	}
	m, phase, err := loadHistory(ctx, tx, profile, chat, device, operation, false)
	if err != nil {
		return err
	}
	if err = historyEpoch(a, m); err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if index < 0 || index >= len(m.Parts) || m.Parts[index].Size != uint64(len(data)) || m.Parts[index].Hash != hex.EncodeToString(hash[:]) {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO history_parts VALUES(?,?,?,?,?,?) ON CONFLICT(profile,chat,device,phase,part) DO UPDATE SET data=excluded.data`, profile, chat, device, phase, index, data)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CommitHistory(ctx context.Context, token string, m protocol.HistoryManifest) (protocol.Receipt, error) {
	if err := m.Validate(s.limits.EnvelopeBytes); err != nil {
		return protocol.Receipt{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.Receipt{}, err
	}
	defer tx.Rollback()
	a, err := historyActor(ctx, tx, token, m)
	if err != nil {
		return protocol.Receipt{}, err
	}
	digest := sha256.Sum256(m.SigningBytes())
	if r, found, err := dedup(ctx, tx, m.ProfileID, a.id, "history:"+m.ChatID, m.OperationID, digest[:]); found || err != nil {
		return r, err
	}
	if err = historyEpoch(a, m); err != nil {
		return protocol.Receipt{}, err
	}
	stored, phase, err := loadHistory(ctx, tx, m.ProfileID, m.ChatID, m.DeviceID, m.OperationID, false)
	if err != nil {
		return protocol.Receipt{}, err
	}
	if phase != 1 || !bytesEqual(stored.SigningBytes(), m.SigningBytes()) {
		return protocol.Receipt{}, ErrReplay
	}
	revision, sequence, err := historyCurrent(ctx, tx, m)
	if err != nil {
		return protocol.Receipt{}, err
	}
	if revision != m.ExpectedRevision || sequence >= m.Sequence {
		return protocol.Receipt{}, ErrConflict
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM history_parts WHERE profile=? AND chat=? AND device=? AND phase=1", m.ProfileID, m.ChatID, m.DeviceID).Scan(&count); err != nil {
		return protocol.Receipt{}, err
	}
	if count != len(m.Parts) {
		return protocol.Receipt{}, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM history_snapshots WHERE profile=? AND chat=? AND device=? AND phase=0", m.ProfileID, m.ChatID, m.DeviceID); err != nil {
		return protocol.Receipt{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE history_snapshots SET phase=0 WHERE profile=? AND chat=? AND device=? AND phase=1", m.ProfileID, m.ChatID, m.DeviceID); err != nil {
		return protocol.Receipt{}, err
	}
	result, err := tx.ExecContext(ctx, "UPDATE profiles SET history_revision=history_revision+1 WHERE id=? AND history_revision<?", m.ProfileID, int64(math.MaxInt64))
	if err != nil {
		return protocol.Receipt{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return protocol.Receipt{}, err
	}
	if n != 1 {
		return protocol.Receipt{}, ErrConflict
	}
	if err = record(ctx, tx, m.ProfileID, a.id, "history:"+m.ChatID, m.OperationID, digest[:], revision+1); err != nil {
		return protocol.Receipt{}, err
	}
	return protocol.Receipt{Revision: revision + 1, OperationID: m.OperationID}, tx.Commit()
}

func (s *Store) HistoryHeads(ctx context.Context, profile, generation, token, chat string) ([]protocol.Head, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, err := authenticate(ctx, tx, profile, generation, token)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT device,revision,sequence,hash FROM history_snapshots WHERE profile=? AND chat=? AND phase=0 AND key_epoch=? AND mode_epoch=? ORDER BY device", profile, chat, a.keyEpoch, a.modeEpoch)
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

func (s *Store) ReadHistory(ctx context.Context, profile, generation, token, chat, device, operation string, part int) ([]byte, uint64, error) {
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
	var keyEpoch, modeEpoch uint64
	query := "SELECT data,revision,key_epoch,mode_epoch FROM history_snapshots WHERE profile=? AND chat=? AND device=? AND operation=? AND phase=0"
	if operation == "" {
		query = "SELECT data,revision,key_epoch,mode_epoch FROM history_snapshots WHERE profile=? AND chat=? AND device=? AND phase=0"
		err = tx.QueryRowContext(ctx, query, profile, chat, device).Scan(&data, &revision, &keyEpoch, &modeEpoch)
	} else {
		err = tx.QueryRowContext(ctx, query, profile, chat, device, operation).Scan(&data, &revision, &keyEpoch, &modeEpoch)
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	if keyEpoch != a.keyEpoch || modeEpoch != a.modeEpoch {
		return nil, 0, ErrEpoch
	}
	if part >= 0 {
		err = tx.QueryRowContext(ctx, "SELECT data FROM history_parts WHERE profile=? AND chat=? AND device=? AND phase=0 AND part=?", profile, chat, device, part).Scan(&data)
		if errors.Is(err, sql.ErrNoRows) {
			err = ErrNotFound
		}
	}
	return data, revision, err
}
