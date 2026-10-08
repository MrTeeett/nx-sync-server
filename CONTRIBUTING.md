# Contributing

Use Go 1.26 or later and the guarded Makefile commands described in README.md.
Format Go code with gofmt. Run `make check` before proposing a change; use
`make race` when changing concurrency, and `make build all` for portability.

Include tests for observable protocol, storage, lifecycle and trust behavior.
Never execute installer, firewall, reset or uninstall tests against the real
host. Use temporary directories and the `host.Runner` process boundary.

Changes to endpoint trust, canonical signing bytes, counters, database schema
and release metadata must update the corresponding documentation. Keep
administrative operations local; do not add privileged HTTP routes.

Contributions are provided under the repository's GPLv3-or-later license.
Preserve existing third-party copyright and license notices. Do not add SPDX
headers to our files.
