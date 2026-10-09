package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"nx-sync-server/internal/protocol"
)

const enrollmentSchema = `
CREATE TABLE bootstrap_tickets (hash BLOB PRIMARY KEY, expires INTEGER NOT NULL, digest BLOB);
CREATE TABLE invitations (hash BLOB PRIMARY KEY, profile TEXT NOT NULL REFERENCES profiles(id), device TEXT NOT NULL, operation TEXT NOT NULL, digest BLOB NOT NULL, box BLOB NOT NULL, key_epoch INTEGER NOT NULL, mode_epoch INTEGER NOT NULL, expires INTEGER NOT NULL, claim_digest BLOB, UNIQUE(profile,operation));
`

func (s *Store) migrateEnrollment(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRowContext(ctx, "SELECT schema_version FROM metadata WHERE id=1").Scan(&version); err != nil {
		return err
	}
	if version == 2 {
		return nil
	}
	if version != 1 {
		return errors.New("unsupported schema")
	}
	if _, err = tx.ExecContext(ctx, enrollmentSchema); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE metadata SET schema_version=2 WHERE id=1"); err != nil {
		return err
	}
	return tx.Commit()
}

// NewBootstrapTicket requires trusted local database access. It grants no host
// administration, and expires after five minutes. Tickets are stored hashed.
func (s *Store) NewBootstrapTicket(ctx context.Context) (string, Identity, int64, error) {
	ticket, hash, err := newToken()
	if err != nil {
		return "", Identity{}, 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", Identity{}, 0, err
	}
	defer tx.Rollback()
	id := Identity{}
	if err = tx.QueryRowContext(ctx, "SELECT store_id,generation FROM metadata WHERE id=1").Scan(&id.StoreID, &id.Generation); err != nil {
		return "", id, 0, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM bootstrap_tickets WHERE expires < unixepoch()-86400"); err != nil {
		return "", id, 0, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM bootstrap_tickets").Scan(&count); err != nil {
		return "", id, 0, err
	}
	if count >= 1024 {
		return "", id, 0, ErrQuota
	}
	expires := time.Now().Unix() + 300
	if _, err = tx.ExecContext(ctx, "INSERT INTO bootstrap_tickets(hash,expires) VALUES(?,?)", hash, expires); err != nil {
		return "", id, 0, err
	}
	return ticket, id, expires, tx.Commit()
}

func (s *Store) ClaimBootstrap(ctx context.Context, c protocol.BootstrapClaim) (Credential, error) {
	control := c.Control
	if !protocol.ValidToken(c.Ticket) || !protocol.ValidToken(c.Token) || c.Ticket == c.Token || control.Validate(s.limits.Devices) != nil || control.ExpectedRevision != 0 || control.KeyEpoch != 1 || control.ModeEpoch != 1 || control.CipherMode != "e2ee" || control.Closed || len(control.Members) != 1 || !ed25519.Verify(control.OwnerPublicKey, control.SigningBytes(), control.Signature) || !ed25519.Verify(control.Members[0].PublicKey, c.SigningBytes(), c.Signature) {
		return Credential{}, ErrForbidden
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
	if generation != control.Generation {
		return Credential{}, ErrGeneration
	}
	hash := sha256.Sum256([]byte(c.Ticket))
	digest := sha256.Sum256(c.SigningBytes())
	var expires int64
	var used []byte
	err = tx.QueryRowContext(ctx, "SELECT expires,digest FROM bootstrap_tickets WHERE hash=?", hash[:]).Scan(&expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrUnauthorized
	}
	if err != nil {
		return Credential{}, err
	}
	result := Credential{ProfileID: control.ProfileID, DeviceID: control.OwnerDeviceID, Generation: generation, Token: c.Token}
	if len(used) != 0 {
		if !bytesEqual(used, digest[:]) {
			return Credential{}, ErrReplay
		}
		if _, err = authenticate(ctx, tx, result.ProfileID, generation, c.Token); err != nil {
			return Credential{}, err
		}
		return result, nil
	}
	if expires <= time.Now().Unix() {
		return Credential{}, ErrUnauthorized
	}
	data, err := json.Marshal(control)
	if err != nil {
		return Credential{}, err
	}
	var existing int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM profiles WHERE id=?", control.ProfileID).Scan(&existing); err != nil {
		return Credential{}, err
	}
	if existing != 0 {
		return Credential{}, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO profiles(id,owner_id,owner_key,revision,control) VALUES(?,?,?,1,?)", control.ProfileID, control.OwnerDeviceID, control.OwnerPublicKey, data); err != nil {
		return Credential{}, err
	}
	tokenHash := sha256.Sum256([]byte(c.Token))
	if _, err = tx.ExecContext(ctx, "INSERT INTO devices(profile,id,public_key,role,token_hash) VALUES(?,?,?,'writer',?)", control.ProfileID, control.OwnerDeviceID, control.Members[0].PublicKey, tokenHash[:]); err != nil {
		return Credential{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE bootstrap_tickets SET digest=? WHERE hash=?", digest[:], hash[:]); err != nil {
		return Credential{}, err
	}
	return result, tx.Commit()
}

func (s *Store) Invite(ctx context.Context, token string, i protocol.Invitation) (int64, error) {
	if !protocol.ValidID(i.ProfileID) || !protocol.ValidID(i.Generation) || !protocol.ValidID(i.OperationID) || !protocol.ValidID(i.DeviceID) || len(i.TicketHash) != 32 || len(i.Box) < 40 || len(i.Box) > 16384 {
		return 0, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	a, err := authenticate(ctx, tx, i.ProfileID, i.Generation, token)
	if err != nil {
		return 0, err
	}
	if a.id != a.ownerID || !ed25519.Verify(a.ownerKey, i.SigningBytes(), i.Signature) {
		return 0, ErrForbidden
	}
	digest := sha256.Sum256(i.SigningBytes())
	var prior []byte
	var expires int64
	err = tx.QueryRowContext(ctx, "SELECT digest,expires FROM invitations WHERE profile=? AND operation=?", i.ProfileID, i.OperationID).Scan(&prior, &expires)
	if err == nil {
		if !bytesEqual(prior, digest[:]) {
			return 0, ErrReplay
		}
		return expires, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if i.ExpectedRevision != a.controlRevision {
		return 0, ErrConflict
	}
	var active int
	var tokenHash []byte
	err = tx.QueryRowContext(ctx, "SELECT active,token_hash FROM devices WHERE profile=? AND id=?", i.ProfileID, i.DeviceID).Scan(&active, &tokenHash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrForbidden
	}
	if err != nil {
		return 0, err
	}
	if active != 1 || len(tokenHash) != 0 || i.DeviceID == a.ownerID {
		return 0, ErrForbidden
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM invitations WHERE profile=? AND expires<unixepoch()-86400", i.ProfileID); err != nil {
		return 0, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM invitations WHERE profile=?", i.ProfileID).Scan(&count); err != nil {
		return 0, err
	}
	if count >= 128 {
		return 0, ErrQuota
	}
	var used int64
	if err = tx.QueryRowContext(ctx, "SELECT (SELECT COALESCE(SUM(size),0) FROM envelopes WHERE profile=?)+(SELECT COALESCE(SUM(length(box)),0) FROM invitations WHERE profile=?)", i.ProfileID, i.ProfileID).Scan(&used); err != nil {
		return 0, err
	}
	if used+int64(len(i.Box)) > s.limits.ProfileBytes {
		return 0, ErrQuota
	}

	expires = time.Now().Unix() + 300
	_, err = tx.ExecContext(ctx, "INSERT INTO invitations(hash,profile,device,operation,digest,box,key_epoch,mode_epoch,expires) VALUES(?,?,?,?,?,?,?,?,?)", i.TicketHash, i.ProfileID, i.DeviceID, i.OperationID, digest[:], i.Box, a.keyEpoch, a.modeEpoch, expires)
	if err != nil {
		return 0, err
	}
	return expires, tx.Commit()
}

type JoinResult struct {
	Credential Credential `json:"credential"`
	Box        []byte     `json:"box"`
}

func (s *Store) ClaimInvitation(ctx context.Context, c protocol.InvitationClaim) (JoinResult, error) {
	if !protocol.ValidID(c.ProfileID) || !protocol.ValidID(c.Generation) || !protocol.ValidID(c.DeviceID) || !protocol.ValidID(c.OperationID) || !protocol.ValidToken(c.Ticket) || !protocol.ValidToken(c.Token) || c.Ticket == c.Token {
		return JoinResult{}, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JoinResult{}, err
	}
	defer tx.Rollback()
	var generation string
	if err = tx.QueryRowContext(ctx, "SELECT generation FROM metadata WHERE id=1").Scan(&generation); err != nil {
		return JoinResult{}, err
	}
	if generation != c.Generation {
		return JoinResult{}, ErrGeneration
	}
	hash, digest := sha256.Sum256([]byte(c.Ticket)), sha256.Sum256(c.SigningBytes())
	var box, used, publicKey, tokenHash []byte
	var active, closed int
	var keyEpoch, modeEpoch, currentKey, currentMode uint64
	var expires int64
	err = tx.QueryRowContext(ctx, `SELECT i.box,i.claim_digest,i.expires,i.key_epoch,i.mode_epoch,d.public_key,d.active,d.token_hash,p.closed,p.key_epoch,p.mode_epoch FROM invitations i JOIN devices d ON d.profile=i.profile AND d.id=i.device JOIN profiles p ON p.id=i.profile WHERE i.hash=? AND i.profile=? AND i.device=?`, hash[:], c.ProfileID, c.DeviceID).Scan(&box, &used, &expires, &keyEpoch, &modeEpoch, &publicKey, &active, &tokenHash, &closed, &currentKey, &currentMode)
	if errors.Is(err, sql.ErrNoRows) {
		return JoinResult{}, ErrUnauthorized
	}
	if err != nil {
		return JoinResult{}, err
	}
	if active != 1 || closed != 0 || !ed25519.Verify(publicKey, c.SigningBytes(), c.Signature) {
		return JoinResult{}, ErrForbidden
	}
	if keyEpoch != currentKey || modeEpoch != currentMode {
		return JoinResult{}, ErrEpoch
	}
	result := JoinResult{Credential: Credential{ProfileID: c.ProfileID, DeviceID: c.DeviceID, Generation: generation, Token: c.Token}, Box: box}
	wantedToken := sha256.Sum256([]byte(c.Token))
	if len(used) != 0 {
		if !bytesEqual(used, digest[:]) || !bytesEqual(tokenHash, wantedToken[:]) {
			return JoinResult{}, ErrReplay
		}
		return result, nil
	}
	if expires <= time.Now().Unix() || len(tokenHash) != 0 {
		return JoinResult{}, ErrUnauthorized
	}
	if _, err = tx.ExecContext(ctx, "UPDATE devices SET token_hash=? WHERE profile=? AND id=?", wantedToken[:], c.ProfileID, c.DeviceID); err != nil {
		return JoinResult{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE invitations SET claim_digest=? WHERE hash=?", digest[:], hash[:]); err != nil {
		return JoinResult{}, err
	}
	return result, tx.Commit()
}
