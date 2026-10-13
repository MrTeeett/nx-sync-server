# Server management by account

An installation has one owner profile. The first successful admission assigns it
atomically; every active enrolled device in that account has the same server role.
Device enrollment still requires account-bound confirmation from a trusted device.
Separate accounts receive separate keys and profiles through one-use, five-minute
owner invitations. Account labels and device names are display metadata, not proof
of Telegram identity.

Only owner-profile credentials can list accounts, issue account invitations,
revoke another account, or read/write encrypted administration packets. A revoke
atomically disables all credentials and pending device invitations of the selected
accounts, expires unused admission invitations, and notifies active event streams.
Old invitation retries cannot renew expired tickets. Local client data remains;
a fresh invitation creates a fresh admitted profile. The owner cannot revoke itself
or lose ownership merely by adding another account. Other accounts' ciphertext is
not exposed by the account list.

Clients retain endpoints and sync keys in their encrypted account store. SSH access,
host fingerprints, private keys, and update preferences use that same protected
store and travel only as account-encrypted packets to trusted owner devices.
These values are excluded from settings exports and bot synchronization. Ordinary
errors, restarts, updates, and pauses do not forget access. Forget access removes
the local SSH record; forget connection removes the complete local connection.

Authenticated server information contains the running daemon's build version and
the last root-helper-confirmed automatic-update policy. Missing status is reported
as unknown. The policy snapshot includes its confirmation time; it is not a live
systemd timer health probe. Automatic checks default to disabled with a 24-hour
interval; configurable intervals are 1–720 hours.

Existing schema-3 installations receive additive management tables. A sole legacy
profile becomes owner. Multiple legacy profiles keep access and require a trusted
operator to choose an owner explicitly; no public request may take ownership.
The SSH wizard asks before performing that migration. The equivalent local command is:

```sh
sudo /opt/nx-syncd/current/nx-syncctl assign-owner --profile PROFILE_ID
```

If account access is lost, a trusted root operator may enroll a replacement profile
and explicitly replace the owner with `assign-owner --profile PROFILE_ID --recover`.
This preserves other profiles and expires outstanding admission invitations.
Root access is the operating-system authority; these roles govern NX operations.
Maintenance clients authenticate owner-profile membership over the verified SSH
connection, sending credentials through stdin rather than arguments.

The new screens and encrypted administration exchange require a compatible daemon
and clients. Update helpers downloaded by a client must also support management;
publishing client binaries alone does not update an installed daemon. An explicit
database reset intentionally removes installation ownership together with profiles.
The installation currently permits at most 1,024 retained profiles and 50 accounts
per list page, with the owner first. Revoked profiles remain retained as tombstones.

Validation covers account role persistence, concurrent first admission, isolation,
whole-account revocation, fresh invitations, paginated lists, encrypted-packet CAS,
signatures, replay handling, and shared quotas. Native Windows core tests use a
private fixture with Linux filesystem adaptations; Linux file guards and systemd
lifecycle still require the normal Linux suite (`go test ./...`).
