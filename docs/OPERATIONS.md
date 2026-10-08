# Installation and operations

Automatic installation targets Linux with systemd/cgroup v2. Administrative
commands run locally as root, normally through an SSH session whose host key
has already been verified. They never run through the public HTTPS API.

## Prepare an offline signed release

The project has no published release feed/key yet. For a private deployment,
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

## Preview and install

```sh
sudo ./nx-syncctl preflight --tls-host <public-IP-or-DNS> --port 18443
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
The future installation UI must expose the same default as a checkbox.
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

## Profiles and devices

The current protocol bootstrap is an explicit local/SSH operation. Clients
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
single-use invitation/QR enrollment is a separate integration task.

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
stable release, matching exact CPU target, a greater sequence, schema 1 and
both matching file hashes. The helper stages private copies, stops its own
socket/service, makes a consistent snapshot, changes the current binary pointer
and checks pinned local HTTPS readiness. Schema migrations and automatic
Internet downloads are not implemented. New schemas fail closed.

Recovery resumes the root-owned journal. A failed update remains pending;
recovery never restores a stale snapshot over newer database writes. The
highest accepted release number prevents metadata replay. SSH termination may
interrupt administration; reconnect and inspect `status`, then `recover`.

Reset stops both units, deletes all profiles/device credentials/settings and
own snapshots, and replaces the store generation. The store ID, TLS identity,
port and system lifecycle metadata remain. Retried recovery of an already
completed reset does not erase new profiles in the new generation.

Uninstall removes owned units, rule and binaries, preserving config, TLS and
database by default. `--purge-data` also removes those data and own snapshots.
A small root-owned audit manifest/journal and the service account remain;
automatic account deletion could affect unrelated files using its numeric UID.
An externally changed unit or firewall rule is left for manual review, with a
pending cleanup status. Reinstallation over retained data is not yet automated.
