# Changelog

## Unreleased

- Reinstallation after a completed owned uninstall: retained data keeps device
  credentials and TLS identity; purged data gets a fresh identity. Ownership,
  publisher trust, release anti-rollback checks and journal recovery remain enforced.
- Direct GitHub downloads on the VPS, explicit stable/dev selection and native
  SSH update controls without selecting a local package or publisher key.
- Opt-in systemd automatic updates with a configurable 1–720 hour interval,
  bounded downloads, artifact checks and compatible executable rollback.
- Stable `vX.Y.Z` release publishing after the full CI checks/build matrix.
- Authenticated state/ETag and bounded server-driven SSE change notifications.
- Single-use bootstrap and owner-approved encrypted device enrollment.
- Native client connection/preview/Ping/SSH setup integration in the NX workspace.
- Additive enrollment schema migration and advanced SSH setup script.
- Unsigned installation after a native warning or explicit CLI acknowledgement;
  invalid signatures still fail. Manual updates need acknowledgement; unattended
  unsigned updates need an explicitly saved automatic-update policy.
- Initial Go HTTPS daemon and local administration helper.
- Signed per-device envelopes and owner controls in SQLite WAL.
- Standalone TLS identity, renewal and HTTPS availability probe.
- Guarded static Linux build matrix and release archive packaging.
- GitHub Actions tests, race checks, full Linux builds, and a rolling dev prerelease.

No public stable release has been published.
