# Protocol 1

The server implements this contract. Matching Android/Desktop adapters now
exist in the NX workspace; full client runtime acceptance remains open.
The server does not implement settings cryptography, merging or key wrapping.

All endpoints require HTTPS. `/health` is public; all `/v1/profiles/...` endpoints
require `Authorization: Bearer <43-char-base64url-token>` and
`X-NX-Generation: <32-char-lowercase-hex>`. IDs are 128-bit values represented
by 32 lowercase hex characters. Tokens contain 256 random bits and are stored
as SHA-256 hashes. Root administration and minting the initial bootstrap ticket
remain local/SSH operations; HTTPS enrollment proves possession of that ticket
or of an owner-approved invitation and the new device's signing key.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/health` | `{ "protocol_version": 1, "status": "ready" }`; 503 uses `not_ready` |
| POST | `/v1/bootstrap` | Claim a locally minted ticket using client-generated owner/control and writer proof |
| POST | `/v1/join` | Claim an invitation with the approved device's writer proof |
| POST | `/v1/profiles/{profile}/invitations` | Owner bearer plus owner signature authorizes one encrypted invitation |
| GET/PUT | `/v1/profiles/{profile}/control` | Read/update owner-signed membership, epochs, mode and closure |
| GET | `/v1/profiles/{profile}/heads` | List committed slots in the current epochs |
| GET | `/v1/profiles/{profile}/state` | Atomic control revision, epochs/mode and committed heads; ETag/304 |
| GET | `/v1/profiles/{profile}/events` | Authenticated SSE changed-state hints, without settings content |
| GET/PUT | `/v1/profiles/{profile}/envelopes/{device}` | Read a current slot / CAS-update the authenticated writer's own slot |

POST/PUT bodies require `Content-Type: application/json`; unknown fields/trailing
JSON are rejected. Counters are **decimal JSON strings**, bounded by signed
64-bit storage. Public keys/payload/signatures use standard padded base64.
Receipts contain string `revision`, `operation_id` and boolean `replayed`.
GET slot/control responses include the committed revision as a quoted ETag.
Readers can read, writers can write their own slot; only the current owner
authority can change control. TLS alone does not prove member authorization.

## State and notifications

`state` returns `control_revision`, `key_epoch`, `mode_epoch`, `cipher_mode`
and `heads`. Each head contains `device_id`, string `revision`/`sequence` and
lowercase-hex `sha256`. One database transaction reads authorization, control
metadata and current heads. The ETag is the quoted hex SHA-256 of its encoded
JSON. Authorization runs before comparing `If-None-Match`, including for 304.

`resume` names the requesting device using the authenticated credential, never
a client-supplied device ID. Its `device_id` is that device and `head` is its
committed head from the same transaction, or JSON null if it has not published.
This lets a valid installation recover after losing its local checkpoint.
Before adopting counters, the client must still verify current owner-signed
membership, envelope ETag, writer signature, account, epochs, payload hash and
authenticated decryption. A hint alone never authorizes a counter reset or a
write. Recovery retains ordinary compare-and-swap, replay and revocation checks;
the next envelope uses the recovered revision and a greater sequence and is
signed by the device. Older clients ignore the additional field; clients can
also recover through a verified own head from an older server's `heads` list.

An event stream first sends the current cursor, then coalesces successful
envelope/control writes into `event: changed` frames. Its only data is JSON
`{"etag":"\"<64-hex-digest>\""}`. Subscribe-before-read closes the initial
notification race. A heartbeat every 45 seconds rechecks authorization/state
and detects local administrative changes; removed devices/closed profiles
lose their stream. Comments use `: keepalive`. Streams expire after 12 hours.

Hints are neither signed settings nor a durable event log. After each hint or
reconnect, clients fetch current state and verify owner/writer signatures,
account/environment, epochs, sequence/counter bounds and ciphertext. A revision
changed between state/control/envelope reads requires a fresh cycle. Stream
writes have an eight-second deadline. At most half of `MaxConnections` are
streams (32 by default); they have a separate capacity from `MaxRequests` and
do not hold a normal request slot or five-second request timeout.

## Enrollment

`nx-syncctl connection-code` mints a hashed, single-use 256-bit bootstrap
ticket, valid for five minutes. Its `nxsync1:` code is unpadded base64url JSON:
version 1, kind `bootstrap`, HTTPS `endpoint`, lowercase-hex SPKI `pin`,
store `generation`, `ticket` and decimal-string `expires_at`.

A bootstrap claim contains `ticket`, an independently client-generated `token`,
initial `control` and a writer `signature`. The owner signs the control; its
revision starts at zero, both epochs at one, E2EE on, one writer/member, open.
The writer signs `NX-SYNC-BOOTSTRAP\0v1\0`, `field(ticket)`, `field(token)` and
raw SHA-256 of the control signing bytes. Claiming inserts the profile/control,
writer hash and consumed-ticket digest in one transaction. No private key is
generated or received by the server. Exact accepted retries remain idempotent;
changed claims fail, and a reset invalidates all tickets.

The main app first owner-signs membership containing the requesting device's
fresh ID/key. An invitation contains `profile_id`, `generation`, `operation_id`,
`device_id`, string `expected_revision`, `ticket_hash`, encrypted `box` and
owner `signature`. Its canonical bytes are `NX-SYNC-INVITE\0v1\0`, the four
IDs in that order as fields, revision as uint64, raw 32-byte ticket hash and
raw SHA-256 of the box. The active member must have no issued token. Boxes are
40–16384 bytes, count toward the profile quota and expire after five minutes.
The box's random wrapping key is independent of the authorization ticket and
is carried only in the privately transferred client invitation code.

A join claim contains profile, generation, device, operation, ticket, token
and writer signature. Canonical bytes are `NX-SYNC-JOIN\0v1\0` followed by
those six strings as fields. The server checks the approved member's key,
active profile, ticket expiry and invitation epochs, then returns `credential`
and the opaque `box`. Exact retries return the same result; other claims cannot
reuse the ticket. The server never receives its wrapping key or profile root.

At most 1024 recent bootstrap tickets and 128 recent invitations/profile are
retained. Expired records become cleanup-eligible after a day; they cannot
authorize a new claim. These endpoints grant no system-administration rights.

## Canonical signatures

`field(x)` means uint32 big-endian byte length followed by x. All counters are
uint64 big-endian. IDs and mode are ASCII. Ed25519 signatures are 64 bytes.
Signature bytes themselves are excluded from the canonical message.

An envelope has these JSON fields: `profile_id`, `device_id`, `generation`,
`operation_id`, `expected_revision`, `sequence`, `key_epoch`, `mode_epoch`,
`cipher_mode`, `payload`, `signature`.

Its signing bytes are:

1. `NX-SYNC-ENVELOPE\0v1\0`.
2. `field(profile_id)`, `field(device_id)`, `field(generation)`, `field(operation_id)`.
3. `expected_revision`, `sequence`, `key_epoch`, `mode_epoch` as uint64.
4. `field(cipher_mode)`, then the 32 raw SHA-256 bytes of payload.

A control's fields are `profile_id`, `generation`, `operation_id`,
`expected_revision`, `key_epoch`, `mode_epoch`, `cipher_mode`, `owner_device_id`,
`owner_public_key`, `members`, `closed`, `signature`, optional `new_owner_signature`.
Each member has `device_id`, 32-byte `public_key` and role `writer`/`reader`.

Its signing bytes are:

1. `NX-SYNC-CONTROL\0v1\0`.
2. `field(profile_id)`, `field(generation)`, `field(operation_id)`.
3. `expected_revision`, `key_epoch`, `mode_epoch` as uint64.
4. `field(cipher_mode)`, `field(owner_device_id)`, `field(owner_public_key)`.
5. One byte for closed (0/1), uint32 member count.
6. Members sorted lexicographically by device ID; each is
   `field(device_id)`, `field(public_key)`, `field(role)`.

Authority transfer additionally requires the new authority's signature over
`NX-SYNC-OWNER-CONFIRM\0v1\0` followed by the full control signing bytes, and the
old authority's normal control signature. The new owner must be a writer.
Reordering members does not change the signature; duplicates are invalid.

An independently encoded fixture is in
`internal/protocol/testdata/envelope-v1.json`; it includes exact bytes, a public
RFC 8032 key, a signature and counters greater than JavaScript's safe integer.

## State guarantees and bounds

Writes check the bearer identity, writer key, signed identifiers, expected
revision and strictly greater sequence for the current slot. SQLite immediate
transactions implement CAS across independent connections. An identical
operation retry returns the original receipt; reusing its ID with different
signed content fails. Receipts retain the last 128 operations per actor/kind;
older retries still face revision checks.

Control epochs never decrease. Mode changes advance the mode epoch. E2EE
member removal/closure advances the key epoch. Old-epoch slots are removed,
inactive IDs cannot be reused and their tokens are cleared. A closed profile
accepts only the original closure receipt retry and owner closure reads.
A reset changes generation, so stale tokens/writes fail before touching state.

### Clear settings while retaining enrolled devices

The owner can clear the profile's settings using the existing control PUT:
keep the key epoch, E2EE mode, owner and members, and increase `mode_epoch`.
Sign with the current owner key and use the current control revision for CAS.
The control update removes preceding envelopes in the same transaction and
retains active device credentials. A stale envelope cannot recreate the copy.
Retry the exact signed operation after a lost response; its stored receipt is
returned without clearing a new copy published afterwards.

Updated [Desktop](../../nx-desktop/.fork/docs/settings-sync.md) and
[Android](../../nx-android/.fork/docs/settings-sync.md) clients verify the signed
forward epoch, reset only their synchronization cache and pause automatic work.
Their local app settings and root/device keys remain intact. Explicitly sending
or enabling automatic sync can start a new cloud copy. Older clients fail closed
on the new mode epoch; their credentials remain valid for an updated client.
`internal/store/clear_settings_test.go` covers deletion, surviving credentials
across restart, stale writers, non-owner rejection and retry after a new copy.
The new regression test has not been run with compilation: the user owns builds.

Defaults: 1 MiB payload, 64 MiB payload quota/profile, 8 active members,
64 connections, 16 active HTTP requests, 1024 total historical device IDs/profile.
Control bodies are limited to 64 KiB;
envelope body limits include base64 overhead. Payload quotas cover live slots, history reservations and retained invitation boxes; metadata/tombstone disk use needs separate operational capacity planning.
The payload's `e2ee`/`plaintext` mode is owner-signed; the server treats the bytes
as opaque and does not independently verify their encryption format.

Error JSON contains only `code`: 401 unauthorized, 403 forbidden, 404 missing,
409 revision/operation/epoch/generation conflict, 410 closed, 413 quota/body
limit, 503 unavailable/overloaded. SQL/path/token details are not returned.

## Message history archives

Task `deleted-inline-2026-10-13` extends [Android](../../nx-android/.fork/docs/message-history.md)
and [Desktop](../../nx-desktop/.fork/docs/message-history.md). Archives are server-only;
the bot backend disables this capability. Clients explicitly authorize archive sync
per account, upload separately by chat, and download only the currently displayed
chat. Bookmarks/revisions and media file bytes are not uploaded. Local per-message
removal/reset and quota pruning do not publish global deletion tombstones.

All routes retain normal bearer/generation authentication and request concurrency,
timeouts and JSON strictness. `chat` is an opaque 32-hex name generated on clients,
never a Telegram chat ID. New routes:

| Method | Route suffix after `/v1/profiles/{profile}` | Purpose |
| --- | --- | --- |
| GET | `/history/{chat}/heads` | Current committed writer heads in this chat, wrapped in `heads` |
| GET/PUT | `/history/{chat}/{device}/manifest` | Read current signed manifest with revision ETag / begin staged upload |
| GET/PUT | `/history/{chat}/{device}/{operation}/{part}` | Read committed ciphertext / idempotently stage an exact signed part |
| POST | `/history/{chat}/{device}/commit` | Verify completeness and atomically replace the writer's chat snapshot |

Part bodies/responses contain base64 `payload`. PUT returns `stored: true`.
Part indices are canonical decimal route components, zero-based. GET requires the
current committed operation and returns its revision ETag; replacement races cause
404 and a fresh client cycle. Manifests are limited to 256 KiB and 1–1024 parts;
each ciphertext is 40 bytes through the configured envelope limit (1 MiB maximum).
Clients use at most 768 KiB plaintext per page and check hashes before decrypting.

Manifest fields are `profile_id`, `device_id`, `generation`, `operation_id`,
`chat_id`, string counters `expected_revision`, `sequence`, `key_epoch`, `mode_epoch`,
`cipher_mode` (always `e2ee`), ordered `parts` (`size` string and 64-hex `sha256`),
and base64 Ed25519 `signature`. Signing bytes are `NX-SYNC-HISTORY\0v1\0`, the
five ID fields in the order listed, four uint64 counters in the order listed,
`field(e2ee)`, uint32 part count, then each part's uint64 size and raw SHA-256.
A head's SHA-256 authenticates these canonical signing bytes, excluding signature.
The independent fixture is `internal/protocol/testdata/history-v1.json` and matches
[the shared fixture](../../nx-shared/vectors/message-history-server.v1.json).

Clients derive the opaque chat name as the first 16 bytes of HMAC-SHA256 using
the profile root and `NX-HISTORY-CHAT\0v1\0`, `field(user_id decimal)`, one
boolean environment byte and `field(canonical peer)`. Canonical peer strings are
`user:<bare ID>`, `chat:<bare ID>`, `channel:<bare ID>`. Actual peer/account IDs,
message IDs, sender, text and native media metadata appear only in ciphertext.
The server can observe grouping, member identities, sizes and timing.

History uses the existing client data cipher/context 1 with a separate AAD:
`NX-SYNC-HISTORY-DATA\0v1\0`, the five manifest IDs, uint64 sequence, key epoch,
mode epoch and zero-based part index. Pages are JSON version 1 with decimal-string
`user_id`, boolean `test`, canonical `peer` and `records`: numeric `id`/`topic`,
decimal-string `saved_at` and base64 network TL `payload`. Both current clients
use layer 229. Android local attachment tails are stripped. Root keys, decryption
and merging remain exclusively in clients; the daemon verifies signatures,
authorization, epochs, counters, part sizes and hashes and stores opaque bytes.

Beginning an upload requires a current writer signature, current epochs and CAS
against that writer's committed chat revision with a greater sequence. Exactly
one incomplete upload per writer/chat is retained; a fresh valid begin can replace
an abandoned stage. Parts must match the signed manifest. Commit checks every
part exists, swaps the complete snapshot and cascading parts in one transaction,
and retains idempotent receipts under actor/kind `history:<opaque chat>`. A retry
of a committed operation returns its original receipt without replacing a later
snapshot. Closure/revocation/epoch advancement removes committed and staged data.
The owner's cloud-clear mode-epoch update also clears archives and keeps device
credentials. Clients pause archive authorization on the signed forward epoch.

Schema 3 adds history tables and a monotonic profile `history_revision` to state
ETags/SSE hints. It migrates schemas 1/2 additively. At most 4096 writer/chat slots
exist per profile. Logical profile quota includes settings, invitations, manifests
and the larger of committed/staged sizes per writer/chat; physical payload usage
can reach twice that quota during replacements. Failed/unfinished uploads leave
old committed data readable. A quota failure keeps the old snapshot and client
archive; the server's configured quota remains an administrative limit.

`internal/store/history_test.go` covers atomic staging/replacement, retry,
tampering, chat isolation, quota inclusion, epoch clearing and restart. Go tests
have not been compiled/run by the agent. `python3 -B scripts/check-history-schema`
checks production SQLite constraints, swap/rollback, quota SQL and cascading
clear without compiling code or touching a live store. Client runtime acceptance
is still required after user builds.
