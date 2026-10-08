package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/ncruces/go-sqlite3/driver"
	"net/url"
	"nx-sync-server/internal/protocol"
	"os"
	"path/filepath"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrConflict     = errors.New("revision conflict")
	ErrReplay       = errors.New("operation reused with different content")
	ErrEpoch        = errors.New("stale key or mode epoch")
	ErrGeneration   = errors.New("server reset")
	ErrClosed       = errors.New("profile deleted")
	ErrQuota        = errors.New("quota exceeded")
	ErrNotFound     = errors.New("not found")
)

type Limits struct {
	EnvelopeBytes, ProfileBytes int64
	Devices                     int
}
type Store struct {
	db     *sql.DB
	limits Limits
}
type Identity struct {
	StoreID    string `json:"store_id"`
	Generation string `json:"generation"`
}
type Credential struct {
	ProfileID  string `json:"profile_id"`
	DeviceID   string `json:"device_id"`
	Generation string `json:"generation"`
	Token      string `json:"token"`
}

const schema = `
CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL, store_id TEXT NOT NULL, generation TEXT NOT NULL);
CREATE TABLE profiles (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, owner_key BLOB NOT NULL, closed INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 0, key_epoch INTEGER NOT NULL DEFAULT 1, mode_epoch INTEGER NOT NULL DEFAULT 1, mode TEXT NOT NULL DEFAULT 'e2ee', control BLOB);
CREATE TABLE devices (profile TEXT NOT NULL REFERENCES profiles(id), id TEXT NOT NULL, public_key BLOB NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, token_hash BLOB UNIQUE, PRIMARY KEY(profile,id));
CREATE TABLE envelopes (profile TEXT NOT NULL, device TEXT NOT NULL, revision INTEGER NOT NULL, sequence INTEGER NOT NULL, key_epoch INTEGER NOT NULL, mode_epoch INTEGER NOT NULL, size INTEGER NOT NULL, hash TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY(profile,device), FOREIGN KEY(profile,device) REFERENCES devices(profile,id));
CREATE TABLE operations (profile TEXT NOT NULL, actor TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, digest BLOB NOT NULL, revision INTEGER NOT NULL, created INTEGER NOT NULL DEFAULT(unixepoch()), PRIMARY KEY(profile,actor,kind,id));
`

func connect(path string, limits Limits) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("database path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("database must be a private regular file")
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", "rw")
	q.Set("_txlock", "immediate")
	for _, pragma := range []string{"busy_timeout(5000)", "foreign_keys(1)", "journal_mode(WAL)", "synchronous(FULL)", "cache_size(-2048)", "wal_autocheckpoint(256)", "journal_size_limit(4194304)"} {
		q.Add("_pragma", pragma)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return &Store{db: db, limits: limits}, nil
}

func Create(ctx context.Context, path string, limits Limits) (_ *Store, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	s, err := connect(path, limits)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, schema); err != nil {
		return nil, err
	}
	id, err := protocol.NewID()
	if err != nil {
		return nil, err
	}
	generation, err := protocol.NewID()
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES(1,1,?,?)", id, generation); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return s, nil
}

func Open(ctx context.Context, path string, limits Limits) (*Store, error) {
	s, err := connect(path, limits)
	if err != nil {
		return nil, fmt.Errorf("open existing database: %w", err)
	}
	var version int
	err = s.db.QueryRowContext(ctx, "SELECT schema_version FROM metadata WHERE id=1").Scan(&version)
	if err != nil || version != 1 {
		_ = s.Close()
		return nil, errors.New("database is uninitialized or has unsupported schema")
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Health(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "SELECT schema_version FROM metadata WHERE id=1").Scan(&version); err != nil {
		return err
	}
	if version != 1 {
		return errors.New("unsupported schema")
	}
	return nil
}
func (s *Store) Identity(ctx context.Context) (Identity, error) {
	var id Identity
	err := s.db.QueryRowContext(ctx, "SELECT store_id,generation FROM metadata WHERE id=1").Scan(&id.StoreID, &id.Generation)
	return id, err
}

func newToken() (string, []byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := sha256.Sum256([]byte(token))
	return token, hash[:], nil
}

// Bootstrap is an administrative local operation, never a public HTTP route.
func (s *Store) Bootstrap(ctx context.Context, deviceKey, ownerKey []byte) (Credential, error) {
	var result Credential
	if len(deviceKey) != ed25519.PublicKeySize || len(ownerKey) != ed25519.PublicKeySize {
		return result, errors.New("Ed25519 public keys required")
	}
	profile, err := protocol.NewID()
	if err != nil {
		return result, err
	}
	device, err := protocol.NewID()
	if err != nil {
		return result, err
	}
	token, hash, err := newToken()
	if err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var generation string
	if err = tx.QueryRowContext(ctx, "SELECT generation FROM metadata WHERE id=1").Scan(&generation); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO profiles(id,owner_id,owner_key) VALUES(?,?,?)", profile, device, ownerKey); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO devices(profile,id,public_key,role,token_hash) VALUES(?,?,?,'writer',?)", profile, device, deviceKey, hash); err != nil {
		return result, err
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	return Credential{ProfileID: profile, DeviceID: device, Generation: generation, Token: token}, nil
}

type actor struct {
	id, role, ownerID, mode              string
	key, ownerKey                        []byte
	controlRevision, keyEpoch, modeEpoch uint64
}

func authenticate(ctx context.Context, tx *sql.Tx, profile, generation, token string) (actor, error) {
	var a actor
	var current string
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM metadata WHERE id=1").Scan(&current); err != nil {
		return a, err
	}
	if generation != current {
		return a, ErrGeneration
	}
	if len(token) != 43 {
		return a, ErrUnauthorized
	}
	hash := sha256.Sum256([]byte(token))
	var active, closed int
	err := tx.QueryRowContext(ctx, `SELECT d.id,d.role,d.public_key,d.active,p.owner_id,p.owner_key,p.closed,p.revision,p.key_epoch,p.mode_epoch,p.mode FROM devices d JOIN profiles p ON p.id=d.profile WHERE d.profile=? AND d.token_hash=?`, profile, hash[:]).Scan(&a.id, &a.role, &a.key, &active, &a.ownerID, &a.ownerKey, &closed, &a.controlRevision, &a.keyEpoch, &a.modeEpoch, &a.mode)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrUnauthorized
	}
	if err != nil {
		return a, err
	}
	if closed != 0 {
		return a, ErrClosed
	}
	if active != 1 {
		return a, ErrUnauthorized
	}
	return a, nil
}

func dedup(ctx context.Context, tx *sql.Tx, profile, actor, kind, id string, digest []byte) (protocol.Receipt, bool, error) {
	var got []byte
	var revision uint64
	err := tx.QueryRowContext(ctx, "SELECT digest,revision FROM operations WHERE profile=? AND actor=? AND kind=? AND id=?", profile, actor, kind, id).Scan(&got, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return protocol.Receipt{}, false, nil
	}
	if err != nil {
		return protocol.Receipt{}, false, err
	}
	if !bytesEqual(got, digest) {
		return protocol.Receipt{}, false, ErrReplay
	}
	return protocol.Receipt{Revision: revision, OperationID: id, Replayed: true}, true, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func record(ctx context.Context, tx *sql.Tx, profile, actor, kind, id string, digest []byte, revision uint64) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO operations(profile,actor,kind,id,digest,revision) VALUES(?,?,?,?,?,?)", profile, actor, kind, id, digest, revision)
	if err != nil {
		return err
	}
	// Old retries remain protected by expected revisions even after bounded dedup retention.
	_, err = tx.ExecContext(ctx, `DELETE FROM operations WHERE profile=? AND actor=? AND kind=? AND id NOT IN (SELECT id FROM operations WHERE profile=? AND actor=? AND kind=? ORDER BY revision DESC LIMIT 128)`, profile, actor, kind, profile, actor, kind)
	return err
}

func (s *Store) Publish(ctx context.Context, token string, e protocol.Envelope) (protocol.Receipt, error) {
	if err := e.Validate(s.limits.EnvelopeBytes); err != nil {
		return protocol.Receipt{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.Receipt{}, err
	}
	defer tx.Rollback()
	a, err := authenticate(ctx, tx, e.ProfileID, e.Generation, token)
	if err != nil {
		return protocol.Receipt{}, err
	}
	if a.controlRevision == 0 {
		return protocol.Receipt{}, ErrConflict
	}
	if a.id != e.DeviceID || a.role != "writer" {
		return protocol.Receipt{}, ErrForbidden
	}
	signed := e.SigningBytes()
	if !ed25519.Verify(a.key, signed, e.Signature) {
		return protocol.Receipt{}, ErrForbidden
	}
	digest := sha256.Sum256(signed)
	if r, found, err := dedup(ctx, tx, e.ProfileID, a.id, "envelope", e.OperationID, digest[:]); found || err != nil {
		return r, err
	}
	if e.KeyEpoch != a.keyEpoch || e.ModeEpoch != a.modeEpoch || e.CipherMode != a.mode {
		return protocol.Receipt{}, ErrEpoch
	}
	var revision, sequence uint64
	var previousSize int64
	err = tx.QueryRowContext(ctx, "SELECT revision,sequence,size FROM envelopes WHERE profile=? AND device=?", e.ProfileID, a.id).Scan(&revision, &sequence, &previousSize)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return protocol.Receipt{}, err
	}
	if revision != e.ExpectedRevision || e.Sequence <= sequence {
		return protocol.Receipt{}, ErrConflict
	}
	var total int64
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(size),0) FROM envelopes WHERE profile=?", e.ProfileID).Scan(&total); err != nil {
		return protocol.Receipt{}, err
	}
	if total-previousSize+int64(len(e.Payload)) > s.limits.ProfileBytes {
		return protocol.Receipt{}, ErrQuota
	}
	data, err := json.Marshal(e)
	if err != nil {
		return protocol.Receipt{}, err
	}
	payloadHash := sha256.Sum256(e.Payload)
	revision++
	_, err = tx.ExecContext(ctx, `INSERT INTO envelopes VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(profile,device) DO UPDATE SET revision=excluded.revision,sequence=excluded.sequence,key_epoch=excluded.key_epoch,mode_epoch=excluded.mode_epoch,size=excluded.size,hash=excluded.hash,data=excluded.data`, e.ProfileID, a.id, revision, e.Sequence, e.KeyEpoch, e.ModeEpoch, len(e.Payload), fmt.Sprintf("%x", payloadHash), data)
	if err == nil {
		err = record(ctx, tx, e.ProfileID, a.id, "envelope", e.OperationID, digest[:], revision)
	}
	if err == nil {
		err = tx.Commit()
	}
	return protocol.Receipt{Revision: revision, OperationID: e.OperationID}, err
}
