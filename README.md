# NX Sync Server

A Go server for synchronizing NX settings. `nx-syncd` serves HTTPS and stores
signed data in SQLite. `nx-syncctl` performs local administrative operations,
including installation over SSH. Content encryption, profile owner keys, and
settings merging remain on client devices.

This is an initial protocol implementation. Android/Desktop UI integration,
device invitations, a public release channel, and PostgreSQL support require
further implementation and validation. The HTTP API does not expose system
management with root privileges.

## License

All original code and documentation in this repository are licensed under the
GNU General Public License version 3 **or any later version**.
The full text is available in [LICENSE](LICENSE). Dependency licenses and notices
are preserved in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
`third_party/licenses/`.

## Building

Requires Linux, Go 1.26+, GNU make, Bash, a systemd user manager, cgroup v2, `flock`,
`tar`, and `sha256sum`. Builds run on a development machine. The resulting static
binaries can be transferred to a server without Go, gcc, glibc, or a systemd user
manager.

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
and invalidates previous tokens. Updates accept a local bundle signed by the
pinned key and verify metadata expiry, the release sequence number, and hashes
of both binaries. A public update channel URL and project key will be added
once the release process is established.

## Development

Do not run installation commands on your development machine for testing.
Service and firewall management tests use a temporary filesystem and mock
system commands. Changes to the cryptographic format require interoperability
tests with the clients. Contribution guidelines are in
[CONTRIBUTING.md](CONTRIBUTING.md).

Architecture reference: `../docs/SETTINGS_SYNC_PLAN.md` in the NX workspace.
