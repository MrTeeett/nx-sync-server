package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"nx-sync-server/internal/protocol"
)

// ErrOwnerUnassigned requires an explicit local owner assignment for legacy profiles.
var ErrOwnerUnassigned = errors.New("server owner requires local migration")

// ErrRevoked rejects every retained credential of a disconnected account.
var ErrRevoked = errors.New("account access revoked")

// ErrInvitationExpired prevents retries from renewing a cancelled invitation.
var ErrInvitationExpired = errors.New("account invitation expired")

const managementSchema = `
CREATE TABLE IF NOT EXISTS server_ownership (id INTEGER PRIMARY KEY CHECK(id=1), owner_profile TEXT NOT NULL DEFAULT '', migration_pending INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS profile_access (profile TEXT PRIMARY KEY REFERENCES profiles(id), admitted INTEGER NOT NULL DEFAULT 1, label TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL DEFAULT(unixepoch()));
CREATE TABLE IF NOT EXISTS device_info (profile TEXT NOT NULL, device TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', platform TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '', seen INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(profile,device), FOREIGN KEY(profile,device) REFERENCES devices(profile,id));
CREATE TABLE IF NOT EXISTS account_invitations (hash BLOB PRIMARY KEY, issuer TEXT NOT NULL, operation TEXT NOT NULL, UNIQUE(issuer,operation));
CREATE TABLE IF NOT EXISTS server_administration (profile TEXT PRIMARY KEY REFERENCES profiles(id), revision INTEGER NOT NULL, data BLOB NOT NULL);
`

// ServerAccess describes an authenticated account's installation management role.
type ServerAccess struct {
	Owner             bool `json:"owner"`
	OwnerAssigned     bool `json:"owner_assigned"`
	MigrationRequired bool `json:"migration_required"`
}

// DeviceInfo contains client-reported labels and the last observed server activity.
type DeviceInfo struct {
	DeviceID   string `json:"device_id"`
	Label      string `json:"label"`
	Platform   string `json:"platform"`
	Version    string `json:"version"`
	LastActive int64  `json:"last_active,string"`
}

// AccountInfo groups all enrolled devices of an admitted encrypted profile.
type AccountInfo struct {
	ProfileID  string       `json:"profile_id"`
	Label      string       `json:"label"`
	Owner      bool         `json:"owner"`
	LastActive int64        `json:"last_active,string"`
	Devices    []DeviceInfo `json:"devices"`
}

// AccountPage is a bounded account list with an optional exclusive continuation ID.
type AccountPage struct {
	Accounts []AccountInfo `json:"accounts"`
	Next     string        `json:"next"`
}

// DeviceDescription contains display-only labels supplied by an authenticated client.
type DeviceDescription struct {
	AccountLabel string `json:"account_label"`
	Label        string `json:"label"`
	Platform     string `json:"platform"`
	Version      string `json:"version"`
}

func (s *Store) migrateManagement(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, managementSchema); err != nil {
		return err
	}
	var count int
	var first string
	if err = tx.QueryRowContext(ctx, "SELECT count(*),COALESCE(min(id),'') FROM profiles").Scan(&count, &first); err != nil {
		return err
	}
	owner, pending := "", count > 1
	if count == 1 {
		owner = first
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO server_ownership(id,owner_profile,migration_pending) VALUES(1,?,?)", owner, pending); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO profile_access(profile,created) SELECT id,0 FROM profiles"); err != nil {
		return err
	}
	return tx.Commit()
}

func registerProfile(ctx context.Context, tx *sql.Tx, profile string) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM profiles").Scan(&count); err != nil {
		return err
	}
	if count > 1024 {
		return ErrQuota
	}
	var owner string
	var pending int
	if err := tx.QueryRowContext(ctx, "SELECT owner_profile,migration_pending FROM server_ownership WHERE id=1").Scan(&owner, &pending); err != nil {
		return err
	}
	if pending != 0 {
		return ErrOwnerUnassigned
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO profile_access(profile) VALUES(?)", profile); err != nil {
		return err
	}
	if owner == "" {
		_, err := tx.ExecContext(ctx, "UPDATE server_ownership SET owner_profile=? WHERE id=1 AND owner_profile='' AND migration_pending=0", profile)
		return err
	}
	return nil
}

func serverAccess(ctx context.Context, tx *sql.Tx, profile string) (ServerAccess, error) {
	var owner string
	var pending int
	err := tx.QueryRowContext(ctx, "SELECT owner_profile,migration_pending FROM server_ownership WHERE id=1").Scan(&owner, &pending)
	return ServerAccess{Owner: owner == profile, OwnerAssigned: owner != "", MigrationRequired: pending != 0}, err
}

// ServerAccess checks membership before revealing the installation's role.
func (s *Store) ServerAccess(ctx context.Context, profile, generation, token string) (ServerAccess, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ServerAccess{}, err
	}
	defer tx.Rollback()
	if _, err = authenticate(ctx, tx, profile, generation, token); err != nil {
		return ServerAccess{}, err
	}
	return serverAccess(ctx, tx, profile)
}

func serverOwner(ctx context.Context, tx *sql.Tx, profile, generation, token string) (actor, error) {
	a, err := authenticate(ctx, tx, profile, generation, token)
	if err != nil {
		return a, err
	}
	access, err := serverAccess(ctx, tx, profile)
	if err != nil {
		return a, err
	}
	if !access.Owner {
		return a, ErrForbidden
	}
	return a, nil
}

// AssignServerOwner is a trusted local migration, never an HTTPS operation.
// It cannot replace an already assigned installation owner.
func (s *Store) AssignServerOwner(ctx context.Context, profile string) error {
	return s.assignServerOwner(ctx, profile, false)
}

// RecoverServerOwner replaces an owner only through explicit trusted local recovery.
func (s *Store) RecoverServerOwner(ctx context.Context, profile string) error {
	return s.assignServerOwner(ctx, profile, true)
}

func (s *Store) assignServerOwner(ctx context.Context, profile string, recoverOwner bool) error {
	if !protocol.ValidID(profile) {
		return ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var active int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM devices d JOIN profiles p ON p.id=d.profile WHERE p.id=? AND p.closed=0 AND d.active=1 AND d.token_hash IS NOT NULL", profile).Scan(&active); err != nil {
		return err
	}
	if active == 0 {
		return ErrNotFound
	}
	result, err := tx.ExecContext(ctx, "UPDATE server_ownership SET owner_profile=?,migration_pending=0 WHERE id=1 AND (owner_profile='' OR ?=1)", profile, recoverOwner)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrConflict
	}
	if recoverOwner {
		if _, err = tx.ExecContext(ctx, "UPDATE bootstrap_tickets SET expires=unixepoch()-1 WHERE digest IS NULL"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func validLabel(value string, max int) bool {
	if len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// DescribeDevice records authenticated, informational labels, never identity proof.
func (s *Store) DescribeDevice(ctx context.Context, profile, generation, token string, d DeviceDescription) error {
	if !validLabel(d.AccountLabel, 256) || !validLabel(d.Label, 128) || !validLabel(d.Version, 64) || (d.Platform != "android" && d.Platform != "desktop") {
		return ErrForbidden
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
	if _, err = tx.ExecContext(ctx, "UPDATE profile_access SET label=? WHERE profile=?", strings.TrimSpace(d.AccountLabel), profile); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO device_info(profile,device,label,platform,version,seen) VALUES(?,?,?,?,?,unixepoch()) ON CONFLICT(profile,device) DO UPDATE SET label=excluded.label,platform=excluded.platform,version=excluded.version,seen=excluded.seen`, profile, a.id, d.Label, d.Platform, d.Version)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ServerAccounts returns bounded pages to the installation owner only.
func (s *Store) ServerAccounts(ctx context.Context, profile, generation, token, after string) (AccountPage, error) {
	page := AccountPage{Accounts: make([]AccountInfo, 0)}
	if after != "" && !protocol.ValidID(after) {
		return page, ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	if _, err = serverOwner(ctx, tx, profile, generation, token); err != nil {
		return page, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT p.id,x.label,MAX(x.created,COALESCE((SELECT max(created) FROM operations WHERE profile=p.id),0),COALESCE((SELECT max(seen) FROM device_info WHERE profile=p.id),0)) FROM profiles p JOIN profile_access x ON x.profile=p.id WHERE x.admitted=1 AND p.closed=0 AND ((p.id=? AND ?='') OR (p.id<>? AND p.id>?)) ORDER BY (p.id=?) DESC,p.id LIMIT 51`, profile, after, profile, after, profile)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		var item AccountInfo
		if err = rows.Scan(&item.ProfileID, &item.Label, &item.LastActive); err != nil {
			break
		}
		item.Owner = item.ProfileID == profile
		item.Devices = make([]DeviceInfo, 0)
		page.Accounts = append(page.Accounts, item)
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil {
		return page, err
	}
	if closeErr != nil {
		return page, closeErr
	}
	if len(page.Accounts) > 50 {
		page.Accounts = page.Accounts[:50]
		page.Next = page.Accounts[49].ProfileID
	}
	for i := range page.Accounts {
		item := &page.Accounts[i]
		rows, err := tx.QueryContext(ctx, `SELECT d.id,COALESCE(i.label,''),COALESCE(i.platform,''),COALESCE(i.version,''),MAX(COALESCE(i.seen,0),COALESCE((SELECT max(created) FROM operations WHERE profile=d.profile AND actor=d.id),0)) FROM devices d LEFT JOIN device_info i ON i.profile=d.profile AND i.device=d.id WHERE d.profile=? AND d.active=1 AND d.token_hash IS NOT NULL ORDER BY d.id`, item.ProfileID)
		if err != nil {
			return page, err
		}
		for rows.Next() {
			var device DeviceInfo
			if err = rows.Scan(&device.DeviceID, &device.Label, &device.Platform, &device.Version, &device.LastActive); err != nil {
				break
			}
			item.Devices = append(item.Devices, device)
		}
		if err == nil {
			err = rows.Err()
		}
		closeErr := rows.Close()
		if err != nil {
			return page, err
		}
		if closeErr != nil {
			return page, closeErr
		}
	}
	return page, nil
}

// InviteAccount admits a separate encrypted profile through a one-use ticket.
func (s *Store) InviteAccount(ctx context.Context, profile, generation, token string, command protocol.ServerCommand) (int64, error) {
	if !protocol.ValidID(command.OperationID) || command.Target != "" || len(command.TicketHash) != 32 {
		return 0, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	a, err := serverOwner(ctx, tx, profile, generation, token)
	if err != nil {
		return 0, err
	}
	if !ed25519.Verify(a.key, command.SigningBytes("invite", profile, generation), command.Signature) {
		return 0, ErrForbidden
	}
	var hash []byte
	var expires int64
	err = tx.QueryRowContext(ctx, `SELECT i.hash,b.expires FROM account_invitations i JOIN bootstrap_tickets b ON b.hash=i.hash WHERE i.issuer=? AND i.operation=?`, profile, command.OperationID).Scan(&hash, &expires)
	if err == nil {
		if !bytesEqual(hash, command.TicketHash) {
			return 0, ErrReplay
		}
		if expires <= time.Now().Unix() {
			return 0, ErrInvitationExpired
		}
		return expires, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM account_invitations WHERE hash IN (SELECT hash FROM bootstrap_tickets WHERE expires<unixepoch()-86400)"); err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM bootstrap_tickets WHERE expires<unixepoch()-86400"); err != nil {
		return 0, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM bootstrap_tickets").Scan(&count); err != nil {
		return 0, err
	}
	if count >= 1024 {
		return 0, ErrQuota
	}
	expires = time.Now().Unix() + 300
	if _, err = tx.ExecContext(ctx, "INSERT INTO bootstrap_tickets(hash,expires) VALUES(?,?)", command.TicketHash, expires); err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO account_invitations(hash,issuer,operation) VALUES(?,?,?)", command.TicketHash, profile, command.OperationID); err != nil {
		return 0, err
	}
	return expires, tx.Commit()
}

// RevokeAccounts invalidates every device and pending device invitation atomically.
// An empty target revokes other accounts while preserving the entire owner account.
func (s *Store) RevokeAccounts(ctx context.Context, profile, generation, token string, command protocol.ServerCommand) ([]string, error) {
	if !protocol.ValidID(command.OperationID) || (command.Target != "" && !protocol.ValidID(command.Target)) || len(command.TicketHash) != 0 {
		return nil, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, err := serverOwner(ctx, tx, profile, generation, token)
	if err != nil {
		return nil, err
	}
	if command.Target == profile || !ed25519.Verify(a.key, command.SigningBytes("revoke", profile, generation), command.Signature) {
		return nil, ErrForbidden
	}
	digest := sha256.Sum256(command.SigningBytes("revoke", profile, generation))
	if _, found, err := dedup(ctx, tx, profile, a.id, "server-revoke", command.OperationID, digest[:]); found || err != nil {
		return []string{}, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT profile FROM profile_access WHERE profile<>? AND admitted=1 AND (?='' OR profile=?)", profile, command.Target, command.Target)
	if err != nil {
		return nil, err
	}
	profiles := make([]string, 0)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		profiles = append(profiles, id)
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	for _, target := range profiles {
		if _, err = tx.ExecContext(ctx, "UPDATE profile_access SET admitted=0 WHERE profile=?", target); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE devices SET active=0 WHERE profile=?", target); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM invitations WHERE profile=?", target); err != nil {
			return nil, err
		}
	}
	var revision uint64
	if err = tx.QueryRowContext(ctx, "SELECT revision FROM server_ownership WHERE id=1").Scan(&revision); err != nil {
		return nil, err
	}
	if len(profiles) != 0 {
		if _, err = tx.ExecContext(ctx, "UPDATE bootstrap_tickets SET expires=unixepoch()-1 WHERE digest IS NULL"); err != nil {
			return nil, err
		}
	}
	if revision >= 1<<63-1 {
		return nil, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "UPDATE server_ownership SET revision=revision+1 WHERE id=1"); err != nil {
		return nil, err
	}
	if err = record(ctx, tx, profile, a.id, "server-revoke", command.OperationID, digest[:], revision+1); err != nil {
		return nil, err
	}
	return profiles, tx.Commit()
}
