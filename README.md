# NX Sync Server

A Go server for synchronizing NX settings. `nx-syncd` serves HTTPS and stores
signed data in SQLite. `nx-syncctl` performs local administrative operations,
including installation over SSH. Content encryption, profile owner keys, and
settings merging remain on client devices.

Android and Desktop integration is now implemented in the NX workspace:
connection codes, owner-approved device invitations, encrypted merging,
native preview, Ping, server change notifications and SSH setup screens.
Client builds and tests on real devices/VPS remain required. GitHub release
downloads and scheduled updates are implemented; PostgreSQL remains future work.
The HTTP API does not expose
system management with root privileges.

## License

All original code and documentation in this repository are licensed under the
GNU General Public License version 3 **or any later version**.
The full text is available in [LICENSE](LICENSE). Dependency licenses and notices
are preserved in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
`third_party/licenses/`.

## Building

Requires Linux, Go 1.26+, GNU make, Bash, a systemd user manager, cgroup v2, `flock`,
`tar`, `sha256sum`, and Python 3.11+. Builds run on a development machine.
The resulting static binaries can be transferred to a server without Go, gcc,
glibc, or a systemd user manager.

```sh
make build all       # both binaries for the full Linux build matrix
make all             # the same build; also the default target for make
make build           # build host architecture only; output in bin/
make check           # module verification, tests, and go vet
make race            # race detector tests on the build host; requires a C compiler
```

The matrix is defined in [packaging/targets.txt](packaging/targets.txt): amd64,
386, ARMv5/v6/v7, arm64, MIPS/MIPS little-endian, MIPS64/MIPS64 little-endian,
ppc64/ppc64le, riscv64, s390x, and loong64. ARM and MIPS use software floating
point. This covers all Linux GOARCH targets in the current Go toolchain, with
separate ARM variants. Other operating systems and new processors require
separate validation.

Build outputs are in `dist/linux-*/`, archives in `dist/`, and checksums in
`dist/SHA256SUMS`. Each archive includes `nx-syncd`, `nx-syncctl`, documentation,
licenses, and installation files. Checksums detect file corruption; update
authenticity is established by a separate release signature, not SHA256SUMS.

All compilers and child processes run in one cgroup with a hard `MemoryMax=4G`
limit, `MemorySwapMax=0`, one build job, and one test worker. The script verifies
the actual values in `/sys/fs/cgroup` **before** running Go. If the limit is not
active, the build stops. `make -j` does not increase parallelism.

## Development snapshots

GitHub Actions runs module verification, tests, go vet, race detector tests,
and the full Linux build matrix on branch pushes, pull requests, and manual
runs. Builds use the same verified 4 GiB cgroup limit and one worker as local
builds. Each run uploads binary archives, a source archive with vendored
dependencies, and `SHA256SUMS` as an artifact retained for 14 days.

Successful builds from `main` update the rolling
[dev prerelease](https://github.com/MrTeeett/nx-sync-server/releases/tag/dev).
Versions use `0.1.0-dev.<commit>`; the release notes link to the commit and
workflow run. Builds from other branches and pull requests publish artifacts
without changing the dev release.

These snapshots are unsigned development archives with an unsigned `release.json`.
The SSH wizard warns that the installer author cannot be verified and allows
explicit continuation. Manual installation/update requires `--allow-unsigned`
for each operation; no publisher key is needed for an unsigned package.
Packages with a present, invalid signature are rejected.
The dev tag moves to the latest successfully published main commit. Pushing a
`vX.Y.Z` tag runs the same checks and publishes a stable release with that version.
Only a successful build publishes assets. Publishing a stable release remains an
explicit maintainer action; the installer never substitutes dev for missing stable.

## Installation platforms

Automatic installation targets Linux with systemd and cgroup v2. Individual
firewalld and UFW rules are supported. An unrecognized firewall requires manual
configuration. The installer does not enable a disabled firewall, reset its
rules, or modify nginx, certificates, ports, or services belonging to other
applications.

OpenWrt uses a different service manager and firewall. A binary targeting a
router's processor does not by itself imply OpenWrt installation support.
Automatic installation on OpenWrt is currently unsupported. SQLite requires
persistent storage with correct locking/mmap support and Linux 3.15 or newer;
Go may impose stricter kernel version requirements. Memory capacity and storage
space for the binaries must be checked on the actual device.

## Quick local start

```sh
make build
bin/nx-syncctl init --dir "$PWD/demo" --tls-host 127.0.0.1 --port 18443
bin/nx-syncd --config "$PWD/demo/config.json"
# In another terminal: init prints the pin, which is a public fingerprint.
bin/nx-syncctl ping --endpoint https://127.0.0.1:18443 --pin <SHA256-SPKI>
```

`init` explicitly creates a new private directory, database, and self-signed
certificate. Reinitializing an existing directory is prohibited. The daemon
refuses to start if the database is missing, so accidental deletion cannot
create an empty store using the previous credentials.

## HTTPS and availability checks

A fresh VPS needs neither nginx nor ACME: the server issues its own ECDSA P-256
certificate with a SAN for the specified IP address or domain and serves
TLS 1.2/1.3 on the selected port. The client obtains the SHA-256 SPKI fingerprint
through a trusted SSH session and checks the certificate's key, name, validity,
and purpose. Certificates are renewed using the same key. Replacing the key
requires explicit pairing again. The system CA trust store is not modified.

`ping` performs `GET /health` with a total timeout of 5 seconds, TLS verification,
and redirects disabled. It reports server availability and HTTPS request time,
including TLS; it is not an ICMP ping or confirmation that a particular profile
has synchronized. The public response contains only the protocol version and
`ready`/`not_ready`. It contains no passwords, profiles, signatures, settings
content, or internal paths.

Proxy checks use `--proxy` or standard proxy environment variables, without
falling back to a direct connection on failure. Installation checks the local
listener separately. Reachability through the provider's firewall, NAT, and
the Internet must be checked from a client device.

## Administration and updates

Detailed installation and maintenance commands are documented in
[docs/OPERATIONS.md](docs/OPERATIONS.md). The API format, signatures, quotas,
and generation reset are described in [docs/PROTOCOL.md](docs/PROTOCOL.md).
Known implementation limits and required validation are listed in
[docs/STATUS.md](docs/STATUS.md).

The port can be selected manually; an occupied port causes an error. Automatic
selection is limited to ports 18443–18543, excluding the kernel's ephemeral and
reserved ports. Selecting ports 80 and 443 is disallowed by default. The installer
reserves the final port with its own systemd socket unit and enables its socket
and service units to start at boot.

The management manifest and operation journal are stored separately from the
synchronization database. Uninstallation preserves data by default; purging
data requires an explicit flag. A database reset replaces the store generation
and invalidates previous tokens. Updates download the selected channel directly
from `MrTeeett/nx-sync-server` on the VPS, or accept a local bundle. Stable is the
default; dev requires explicit selection. Signed packages use the installed
publisher pin. Unsigned manual updates require `--allow-unsigned`; automatic
unsigned updates require a separate explicit saved policy. Both paths check
expiry, release sequence, CPU target, schema and binary hashes.

Automatic updating is off by default. Its check interval defaults to 24 hours
and can be set between 1 and 720 hours. An owned systemd timer runs a separate
root helper with a 512 MiB hard memory limit; `nx-syncd` stays unprivileged.
Updates preserve the port, TLS key, settings and existing firewall rules.
Compatible prior executables are retained for `rollback` and restored if a new
release fails its local health check. Rollback keeps the live database, including
new settings and revoked credentials. Schema-1 executables cannot open a migrated
schema-2 database, and legacy manifests without retained release metadata cannot
provide rollback on their first upgrade. Protocol version 1 remains supported.

## Connect Android and Desktop

In NX, open **Settings transfer → Sync server**. Settings exchange starts off.

1. For an installed server, generate a five-minute connection code through a
   trusted SSH session:

   ```sh
   sudo /opt/nx-syncd/current/nx-syncctl connection-code \
     --endpoint https://<public-IP-or-DNS>:18443 --out /root/nx-connection.txt
   ```

   Transfer that private file's code to the first app. Its owner, device,
   encryption and recovery keys are generated locally; private keys are never
   sent to the server. `--out -` explicitly returns a code in JSON for the
   native SSH wizard. Keep codes out of logs and shared terminals.
2. Select fields and directions. Review/apply the server's values, or explicitly
   publish the selected local values, before enabling automatic sync.
3. On the second app, create **this device's request**. Approve it using
   **Add a device** on the main app, then enter its five-minute invitation on
   the requesting app. The invitation includes an independent encryption key;
   deliver it privately. Each device keeps its own writer key and token.
4. Use **Ping** to check HTTPS identity/readiness and request time. Use preview
   and a two-device edit to verify actual settings delivery.

The foreground client maintains one authenticated HTTPS event stream (SSE).
It carries only a changed-state cursor; clients fetch and authenticate encrypted
envelopes separately. Healthy streams replace repeated foreground polling.
Reconnect always compares current state, so a missed notification loses no
committed settings. Android closes the stream when the app goes into the
background and uses OS-scheduled jobs, with a minimum periodic interval of
15 minutes and possible additional system delays. Failed streams use bounded
reconnection/backoff and conditional state requests.

For a fresh VPS, **Set up server over SSH** confirms the SSH host fingerprint
and downloads the correct CPU archive on the VPS. Leave **Use development version**
unchecked for stable; check it to use the rolling dev prerelease. The VPS needs
`curl` or `wget`, `tar`, `gzip` and `sha256sum`, with trusted HTTPS CA certificates;
no Go compiler is installed. A warning with **Cancel** / **Continue** explains
unsigned installer execution. No local package directory or publisher-key field
is required for the current unsigned releases. Invalid signatures remain rejected.
The wizard previews the selected port/firewall and asks for Install.
**Update sync server** opens SSH maintenance with the same channel selection,
manual update, automatic update checkbox and check interval. Saving the automatic
settings also requires authorization for future unsigned packages when enabled.
Desktop's SSH wizard requires OpenSSH and
currently supports a selected direct route. It stops while an app proxy is
active; ordinary HTTPS sync follows the compatible selected proxy.
The online command-line equivalent is [scripts/setup-online](scripts/setup-online).
[scripts/setup](scripts/setup) remains available for trusted offline bundles.
Installation and update instructions are in [docs/OPERATIONS.md](docs/OPERATIONS.md).

**Forget this device's connection** clears only its local sync keys/cache.
It retains app settings and server data and does not revoke server credentials.
Forgetting the main device loses its local owner key and requires a new profile
to restore management. Root-key rotation, revocation/authority-transfer screens,
bot transport and network/resource application are not part of this client slice.

## Development

Do not run installation commands on your development machine for testing.
Service and firewall management tests use a temporary filesystem and mock
system commands. Changes to the cryptographic format require interoperability
tests with the clients. Contribution guidelines are in
[CONTRIBUTING.md](CONTRIBUTING.md).

Architecture reference: `../docs/SETTINGS_SYNC_PLAN.md` in the NX workspace.
