# Implementation status

This is an unreleased initial server implementation. Availability through
public Internet and foreign-service coexistence need tests on representative
VPS images before declaring the installer production-ready.

Implemented paths:

- HTTPS daemon, unprivileged systemd service and inherited listener.
- Explicit SQLite creation, signed controls/envelopes, CAS, hashed tokens,
  durable revocation/closure and generation reset.
- Atomic authenticated state/ETag, bounded SSE change hints, local five-minute
  bootstrap tickets and owner-approved encrypted device invitations.
- Additive SQLite schema 1 → 2 migration preserving existing profiles.
- Advanced SSH setup script and native Android/Desktop connection, Ping,
  merge/preview/automatic-sync and SSH wizard source in the NX
  workspace. These client changes have not been compiled or accepted on devices.
- CLI HTTPS ping with pin/SAN/validity checks, deadlines, proxy and cancellation.
- Local install/status/recover/update/reset/uninstall with an exclusive lock,
  root-owned manifest/journal and owned unit/rule checks.
- Signature-pinned offline release bundles, target/expiry/sequence/hash checks,
  snapshots and recovery preserving the live database.
- Unsigned manifests and explicit installer warnings/continuation in both
  native wizards; per-operation CLI acknowledgement with `--allow-unsigned`.
  Present invalid signatures remain rejected. These changes have not been built.
- Architecture-selected GitHub downloads on the VPS, default stable with explicit
  dev selection, native SSH manual updates and automatic-update settings.
- Opt-in owned root update timer, configurable interval, metadata/digest checks
  before service interruption, and retained compatible executable rollback
  preserving the live SQLite database. Legacy manifests without release metadata
  do not support rollback on their first upgrade.
- Full static Linux cross-build matrix, binary/source archives and licenses.
- GitHub Actions workflow for guarded tests/builds, artifacts and a rolling
  unsigned dev prerelease after successful main builds, plus stable `vX.Y.Z`
  publication after successful tagged builds.

Remaining acceptance work:

- Client compilation, native vault/JNI linkage, two-device convergence and
  background/battery/TLS/SSH tests. The user requested no further builds during
  this integration; new enrollment/state/SSE/update Go tests are written but
  unexecuted. Eight bootstrap tests pass with synthetic archives and fake HTTPS
  tools; this does not establish a real GitHub/VPS or native client result.
- Client owner transfer/revocation/key rotation, bot transport, plaintext mode
  migration and dedicated network/resource apply adapters.
- Actual root install/boot/SSH interruption tests on Ubuntu/Debian/Fedora images
  with firewalld/UFW, IPv6, external ingress and existing nginx/services.
- Runtime testing on non-amd64 processors. Cross-compilation proves compilation
  and ELF target properties; it does not prove hardware/runtime acceptance.
- Stable signed publishing identity, key rotation policy, comprehensive signed
  metadata (TUF), future non-additive migrations and
  old-release cleanup. Existing schema-1 installations need the new independently
  verified helper for a schema-2 upgrade; the old helper rejects that bundle.
- Reinstallation over retained data, interrupted setup/update/configuration
  acceptance, and physical disk/metadata/history budgets and measurements.
- PostgreSQL/shared-store lifecycle and cluster-wide maintenance fencing.
- OpenWrt/procd/firewall4 installation and tests (deferred by user request).

Build and behavior validation results are recorded by the guarded tools and
the workspace implementation plan. No actual VPS has been modified during
development, no public release/key has been published, and no client acceptance
task is marked complete merely because the Go server builds.
