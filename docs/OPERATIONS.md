# Installation and operations

Automatic installation targets Linux with systemd/cgroup v2. Administrative
commands run locally as root, normally through an SSH session whose host key
has already been verified. They never run through the public HTTPS API.

## Prepare an offline signed release

Public GitHub releases currently have no publishing signature. For a private deployment,
an operator can create an offline publishing identity and explicitly distribute
its public key. Keep the private key off the synchronization VPS.

```sh
NX_VERSION=0.1.0 make build all
mkdir -m 700 publisher
dist/linux-amd64/nx-syncctl release-keygen --out publisher/publisher.key
# This example's build host is amd64; use the build host's matching nx-syncctl.
dist/linux-amd64/nx-syncctl sign-release \
  --bundle dist/linux-amd64 --private-key-file publisher/publisher.key \
  --version 0.1.0 --target linux-amd64 --sequence 1 \
  --expires "$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)"
```

Use an expiration in the future, at most 90 days away.
Sign each target independently with the same public publishing root.
The signed `release.json` belongs beside both binaries. Transport/extract the
bundle to a root-controlled directory on the VPS before installing. Repack an
archive after signing; `make build all` produces unsigned build artifacts.
Distribute the matching source archive along with binary distributions.

For manually transferring a target bundle, an optional ZIP packager is available:

```sh
scripts/package-client-bundle dist/linux-amd64 nx-sync-server-linux-amd64-signed.zip
```

This serial packager verifies a hard cgroup limit before writing. It includes
the two binaries, signed manifest, README and dependency/GPL notices. Signature
trust is checked by the local administrative helper. Native SSH wizards download
on the VPS instead of accepting ZIPs/directories. Use the local CLI and distribute
the publisher public key through a trusted channel for private signed deployments.

## Use an unsigned development build

`make build` and `make build all` create an unsigned schema-2 `release.json`
containing the exact target, version, file sizes and SHA-256 hashes. Its channel
is `dev`, its sequence is the build's Unix timestamp, and it expires after 30
days. There is no claim about who authored these files. New dev archives include
this metadata; older archives without it need to be rebuilt from current sources.

Both native SSH wizards download the selected GitHub release directly on the VPS
and warn **before executing the installer on the
VPS**: the installer author and authenticity cannot be verified, and running it
as administrator may compromise the server. Choose **Cancel** or **Continue**.
An unsigned package does not require a publisher public key. A package with a
present, invalid signature is rejected rather than offered as unsigned.

For a trusted SSH session, acknowledge the warning for this operation explicitly:

```sh
sudo ./scripts/setup --bundle /root/nx-dev --allow-unsigned \
  --tls-host <public-IP-or-DNS> --port 18443
```

The script/helper print the warning to stderr; stdout remains machine-readable.
Architecture, schema, expiry, sequence, size and hash checks remain required.
These checks detect incompatible or changed files; unsigned hashes do not prove
their publisher. The installation/status journal records `unsigned:true`.
This acknowledgement alone does not enable automatic updates. Enabling them with
`--auto-update` or saving `update-settings --enabled --allow-unsigned` explicitly
authorizes unattended unsigned updates for the configured channel.

## Download and install on a fresh VPS

Use the app's SSH wizard, or copy `scripts/setup-online` and
`scripts/bootstrap-online` from a trusted checkout into the same directory on
the VPS. No build tools are needed there. Linux/systemd, cgroup v2, HTTPS CA
certificates, `curl` or `wget`, `tar`, `gzip` and `sha256sum` are required.

```sh
sudo scripts/setup-online --channel stable --allow-unsigned \
  --tls-host <public-IP-or-DNS> --port 0
# Explicitly select dev while stable is not yet published:
sudo scripts/setup-online --channel dev --allow-unsigned \
  --tls-host <public-IP-or-DNS> --port 18443
```

Stable uses the latest non-prerelease assets; dev uses only the `dev` prerelease.
A missing stable release is an error, never an implicit dev fallback. The known
bootstrap script downloads/checks the archive into its own private temporary
directory and extracts only three fixed files with decompression/output limits.
SHA256SUMS and HTTPS protect transport integrity; unsigned packages still cannot
identify their publisher. The warning must be acknowledged before root execution.

First publish the updated server source and wait for its CI artifacts: older dev
assets do not understand the new online/update commands. Pushing a `vX.Y.Z` tag
publishes stable after all checks. The current manifests expire after 30 days;
publish fresh artifacts before they expire. An expired package is rejected,
while an already installed server keeps running.

## Preview and install

```sh
sudo ./nx-syncctl preflight --bundle /root/nx-release \
  --trust-key <trusted-base64-public-key> --tls-host <public-IP-or-DNS> --port 18443
sudo ./nx-syncctl install --bundle /root/nx-release \
  --trust-key <trusted-base64-public-key> --tls-host <public-IP-or-DNS> \
  --port 18443 --memory-mib 256
```

Omit `--port` or pass zero to select within 18443–18543. Preview does not hold
a port for a later installation. Installation's final listener is owned by
`nx-syncd.socket`. A manually selected busy port fails. Automatic selection can
retry a later candidate only when the earlier bind is confirmed busy.

`--block-web-ports=true` is the default. Explicitly pass
`--block-web-ports=false` if you intend to use 80 or 443 and the port is free.
Both native installation screens expose the same default as a checkbox.
`--bind` specifies a numeric local IP; the default is 0.0.0.0.
IPv4 and IPv6 binds retain their requested family; `--bind ::` is IPv6-only.

The installer creates its own unprivileged system account, versioned binaries,
root-owned config/private key, service-writable database/certificate directory,
systemd socket/service and owned firewall rule. Both units are enabled for boot.
The service has a hard memory budget and no root privileges/capabilities.

For firewalld with multiple active zones, specify `--firewall-zone` for ingress.
Unknown firewall configurations stop automatic setup until an administrator
configures ingress and explicitly uses `--allow-manual-firewall`. No firewall is
enabled/reset, and no nginx or foreign service is configured/restarted. An
inactive/absent firewall is not a promise that a provider's external firewall
allows access. Run the HTTPS ping from the actual client afterward.

The installer prints a public SPKI fingerprint. Transfer it through the same
verified SSH session and bind the client to that exact server identity.

For advanced users, run from the repository's script or a trusted copy:

```sh
sudo scripts/setup --bundle /root/nx-release \
  --trust-key <trusted-base64-public-key> --tls-host <public-IP-or-DNS> \
  --port 18443
```

It invokes `nx-syncctl setup`, which installs, checks local readiness and
returns a private five-minute connection code. Only run a bundle's helper
after independently trusting its publisher/signature. The returned code must
not be copied into shared logs. `install` without `setup` omits that code.
Automatic firewall handling covers supported host firewalls; the VPS provider's
external firewall/security group may still need an inbound rule for this port.

## Health and status

```sh
./nx-syncctl ping --endpoint https://<public-IP-or-DNS>:18443 --pin <SPKI>
sudo /opt/nx-syncd/current/nx-syncctl status
sudo systemctl status nx-syncd.socket nx-syncd.service
sudo journalctl -u nx-syncd.service
```

Local readiness and external reachability are separate checks. The status
includes the root-owned manifest and operation journal, without device tokens.
Persistent administration files live in `/var/lib/nx-syncctl`, outside
`/var/lib/nx-syncd/settings.sqlite`.

## Connection codes and devices

For an existing schema-2 server, mint a code through trusted SSH:

```sh
sudo /opt/nx-syncd/current/nx-syncctl connection-code \
  --endpoint https://<public-IP-or-DNS>:18443 --out /root/nx-connection.txt
```

The new private file contains one five-minute `nxsync1:` code. The native
wizard uses `--out -` to receive the same secret in bounded JSON over SSH.
The code binds HTTPS origin, SPKI and store generation. Do not use a reverse
proxy with a different certificate key as that origin; direct access on the
selected port is the implemented pairing path. Upgrade/restart an older daemon
before issuing codes: native clients require state/enrollment/events endpoints.

The first app generates the owner key, root key, device key and token locally,
then claims the ticket by signing its initial control. No private key is sent
to the server. Sync remains paused until the user reviews cloud values or
explicitly publishes local values and enables automatic exchange.

An additional app generates its own device request. The main app approves that
request and gives it a five-minute invitation containing a separate wrapping
key. Treat the invitation as a secret. Expired unused invitations can be
reissued by repeating Add a device. Exact accepted enrollment retries preserve
identity; a fresh enrollment never clones another device's writer credentials.

## Low-level administrative credentials

The low-level `bootstrap` command is an explicit local/SSH operation. Clients
generate their own Ed25519 writer and owner-authority keys; supply **public**
keys only. The credential is written to a new private file, never printed.

```sh
sudo /opt/nx-syncd/current/nx-syncctl bootstrap \
  --device-key <client-public-writer-key> --owner-key <client-public-owner-key> \
  --out /root/device-credential.json
```

The owner must publish a signed control before any envelope upload. Additional
devices are listed in an owner-signed control; `issue-credential --profile ID
--device ID --out FILE` then issues/rotates a token only for a currently active
signed member. Transfer credentials privately to the intended client. Native
single-use invitation enrollment uses the HTTPS flow above. QR/short-code PAKE
and client key rotation/owner-transfer/revocation UI remain later work.

Owners revoke devices by publishing a new signed control without that member;
E2EE revocation also advances the key epoch. The revoked ID remains a tombstone
and cannot be re-added. A new enrollment uses a fresh device ID. Closing one's
profile uses `closed:true`; it is durable and cannot be reopened by an old token.
Removing local configuration on a device alone does not revoke its server token.

## Update, reset and removal

```sh
sudo /opt/nx-syncd/current/nx-syncctl update --bundle /root/newer-signed-release
sudo /opt/nx-syncd/current/nx-syncctl reset-db --confirm-reset
sudo /opt/nx-syncd/current/nx-syncctl uninstall
# Use a retained copy of nx-syncctl after uninstall removed the installed binary.
sudo ./nx-syncctl uninstall --purge-data
sudo ./nx-syncctl recover
```

Updates accept the installation's original public signing key, an unexpired
stable release, matching exact CPU target, a greater sequence, schema 2 and
both matching file hashes. The helper stages private copies, stops its own
socket/service, makes a consistent snapshot, changes the current binary pointer
and checks pinned local HTTPS readiness. The current additive enrollment
migration upgrades SQLite schema 1 to 2 without removing existing profiles.
Internet downloads use the selected GitHub channel. Unsupported schemas and
future non-additive migrations fail closed. Protocol version 1 remains supported;
this does not promise arbitrary older executables can open a newer database.

For an unsigned development update, use `update --bundle /root/newer-dev
--allow-unsigned`. The helper warns again and checks a greater sequence, expiry,
schema, target and both hashes. The unsigned setting in `status` describes the
currently installed version; it alone grants no permission to accept the next package.
Any existing publisher pin is retained. An installation made without a publisher
key cannot verify signed updates until a trusted publishing identity is configured;
publisher-key enrollment/rotation remains future work.

Current signed bundles declare schema **2**. An original schema-1 helper rejects
them; use the new independently verified helper with `update --bundle ...`
to upgrade that installation. It uses the installation's existing publisher
key and requires a higher release sequence. After migration an original
schema-1 daemon cannot open the database: do not switch `current` back to it.
Recovery preserves the live database and never restores an old snapshot over
newer writes. A cold schema migration/upgrade still needs runtime acceptance.

Recovery resumes the root-owned journal. A failed update remains pending;
recovery never restores a stale snapshot over newer database writes. The
highest accepted release number prevents metadata replay. SSH termination may
interrupt administration; reconnect and inspect `status`, then `recover`.

## Online and automatic updates

```sh
# Stable is the default when --bundle is omitted.
sudo /opt/nx-syncd/current/nx-syncctl update --channel stable --allow-unsigned
sudo /opt/nx-syncd/current/nx-syncctl update --channel dev --allow-unsigned

# Explicitly authorize automatic unsigned releases from the selected channel.
sudo /opt/nx-syncd/current/nx-syncctl update-settings \
  --enabled --channel dev --interval 24h --allow-unsigned
sudo /opt/nx-syncd/current/nx-syncctl update-status
sudo systemctl status nx-sync-update.timer
sudo journalctl -u nx-sync-update.service
# Stop automatic checks without changing the installed release.
sudo /opt/nx-syncd/current/nx-syncctl update-settings \
  --enabled=false --channel stable --interval 24h

# Explicitly restore retained, hash-checked compatible executables.
sudo /opt/nx-syncd/current/nx-syncctl rollback
```

Automatic checks default off, stable, 24 hours. Intervals range from 1 to 720
hours. The first enabled check is about five minutes later, with up to five
minutes of jitter; subsequent checks use the configured interval after the last
run. A root-owned separate timer/service performs management under the existing
exclusive lock. Its 512 MiB hard memory limit and reduced CPU/IO priority do not
change the daemon's unprivileged account or foreign services. Disabling the
policy prevents downloaded updates from being applied after an in-flight check.
Updating the configuration validates ownership and never replaces foreign units.

GitHub metadata/digests avoid downloading an unchanged release on every check.
Downloads have HTTPS/redirect/size/time limits, then target/channel/expiry/schema,
sequence and binary hashes are checked before the owned daemon stops. New stable
updates cannot downgrade a stable version. Port, TLS identity, settings and
owned ingress rules remain unchanged. A failed new health check restores tracked
compatible schema-2 executables; an interrupted operation may still need `recover`.
Rollback never copies an old SQLite snapshot over the live database, preserving
new writes and revocations. A schema-1 downgrade is prohibited. Legacy manifests
without stored release metadata cannot roll back their first upgrade; later
tracked compatible versions can. The highest accepted sequence remains retained
after rollback so automatic updates do not repeatedly apply the failed release.

The app's **Update sync server** screen performs the same operations over SSH.
The public synchronization API never accepts root management requests.

Reset stops both units, deletes all profiles/device credentials/settings and
own snapshots, and replaces the store generation. The store ID, TLS identity,
port and system lifecycle metadata remain. Retried recovery of an already
completed reset does not erase new profiles in the new generation.

Uninstall also disables/removes the owned update timer/service and saved policy.
It removes owned daemon units, rule and binaries, preserving config, TLS and
database by default. `--purge-data` also removes those data and own snapshots.
A small root-owned audit manifest/journal and the service account remain;
automatic account deletion could affect unrelated files using its numeric UID.
An externally changed unit or firewall rule is left for manual review, with a
pending cleanup status. Reinstallation over retained data is not yet automated.
