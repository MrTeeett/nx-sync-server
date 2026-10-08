# Implementation status

This is an unreleased initial server implementation. Availability through
public Internet and foreign-service coexistence need tests on representative
VPS images before declaring the installer production-ready.

Implemented paths:

- HTTPS daemon, unprivileged systemd service and inherited listener.
- Explicit SQLite creation, signed controls/envelopes, CAS, hashed tokens,
  durable revocation/closure and generation reset.
- CLI HTTPS ping with pin/SAN/validity checks, deadlines, proxy and cancellation.
- Local install/status/recover/update/reset/uninstall with an exclusive lock,
  root-owned manifest/journal and owned unit/rule checks.
- Signature-pinned offline release bundles, target/expiry/sequence/hash checks,
  same-schema snapshots and recovery preserving the live database.
- Full static Linux cross-build matrix, binary/source archives and licenses.

Remaining acceptance work:

- Native Android/Desktop protocol adapters, invitation enrollment, profile key
  wrapping/merge and installation UI, including the Ping button and port policy
  checkbox. The CLI implements the underlying controls and ping behavior.
- Actual root install/boot/SSH interruption tests on Ubuntu/Debian/Fedora images
  with firewalld/UFW, IPv6, external ingress and existing nginx/services.
- Runtime testing on non-amd64 processors. Cross-compilation proves compilation
  and ELF target properties; it does not prove hardware/runtime acceptance.
- Project publishing identity/feed, key rotation policy, automated fetching,
  comprehensive signed metadata (TUF), schema migrations and old-release cleanup.
- Reinstallation over retained data, automatic root maintenance jobs surviving
  SSH termination, and physical disk/metadata/history budgets and measurements.
- PostgreSQL/shared-store lifecycle and cluster-wide maintenance fencing.
- OpenWrt/procd/firewall4 installation and tests (deferred by user request).

Build and behavior validation results are recorded by the guarded tools and
the workspace implementation plan. No actual VPS has been modified during
development, no public release/key has been published, and no client acceptance
task is marked complete merely because the Go server builds.
