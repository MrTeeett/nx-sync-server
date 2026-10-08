# Protocol 1

The current server contract is implemented here and needs matching client
adapters before Android/Desktop integration is accepted. It does not implement
the client's settings schema, AES-GCM, merge algorithm or profile key wrapping.

All endpoints require HTTPS. `/health` is public; all `/v1/profiles/...` endpoints
require `Authorization: Bearer <43-char-base64url-token>` and
`X-NX-Generation: <32-char-lowercase-hex>`. IDs are 128-bit values represented
by 32 lowercase hex characters. Tokens contain 256 random bits and are stored
as SHA-256 hashes. Administrative enrollment is local/SSH only.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/health` | `{ "protocol_version": 1, "status": "ready" }`; 503 uses `not_ready` |
| GET/PUT | `/v1/profiles/{profile}/control` | Read/update owner-signed membership, epochs, mode and closure |
| GET | `/v1/profiles/{profile}/heads` | List committed slots in the current epochs |
| GET/PUT | `/v1/profiles/{profile}/envelopes/{device}` | Read a current slot / CAS-update the authenticated writer's own slot |

PUT bodies require `Content-Type: application/json`; unknown fields/trailing
JSON are rejected. Counters are **decimal JSON strings**, bounded by signed
64-bit storage. Public keys/payload/signatures use standard padded base64.
Receipts contain string `revision`, `operation_id` and boolean `replayed`.
GET slot/control responses include the committed revision as a quoted ETag.
Readers can read, writers can write their own slot; only the current owner
authority can change control. TLS alone does not prove member authorization.

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
envelope body limits include base64 overhead. Payload quotas apply to live
slots; metadata/tombstone disk use needs separate operational capacity planning.
The payload's `e2ee`/`plaintext` mode is owner-signed; the server treats the bytes
as opaque and does not independently verify their encryption format.

Error JSON contains only `code`: 401 unauthorized, 403 forbidden, 404 missing,
409 revision/operation/epoch/generation conflict, 410 closed, 413 quota/body
limit, 503 unavailable/overloaded. SQL/path/token details are not returned.
