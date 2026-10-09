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

Defaults: 1 MiB payload, 64 MiB payload quota/profile, 8 active members,
64 connections, 16 active HTTP requests, 1024 total historical device IDs/profile.
Control bodies are limited to 64 KiB;
envelope body limits include base64 overhead. Payload quotas cover live slots and retained invitation boxes; metadata/tombstone disk use needs separate operational capacity planning.
The payload's `e2ee`/`plaintext` mode is owner-signed; the server treats the bytes
as opaque and does not independently verify their encryption format.

Error JSON contains only `code`: 401 unauthorized, 403 forbidden, 404 missing,
409 revision/operation/epoch/generation conflict, 410 closed, 413 quota/body
limit, 503 unavailable/overloaded. SQL/path/token details are not returned.
