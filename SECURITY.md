# Security reports

Do not include tokens, private keys, signed invitation material or settings
payloads in public bug reports. Describe affected versions and the minimal
reproduction with synthetic data.

A project-specific private reporting address has not been configured yet.
Until one is configured, contact the repository owner privately. This document
does not invent an email address or public release identity.

The daemon must remain unprivileged. Only the local administrative helper may
manage owned services, firewall rules, binaries and database lifecycle. TLS
pinning, signed controls, revocation tombstones, revision checks, generation
checks and pinned update verification are protocol properties to preserve.
