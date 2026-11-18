# Deployment and operations

The signed OPNsense Beta package is available for FreeBSD 15 amd64. Use a
dedicated Linux test host and retain independent management access to the host
and router. The [validation ledger](handoff/validation.md) records accepted
source revisions and measurements. W5–W7, public-provider acceptance and the
complete backup and restore drill remain open.

## Host and network

Use Docker Engine 28 or newer with default NAT bridge behavior and Compose
supporting `!override` (2.24.4 or newer). The generated loopback publications rely
on that isolation. Review direct routing, custom bridge modes and additional
proxies separately. Runtime services do not receive Docker administration access.

Choose a console hostname outside the device wildcard suffix, a dedicated unused
edge subnet, a new deployment directory and a separate protected backup parent.
Configure console and wildcard DNS for the relay address. The bundled HTTPS proxy
uses TCP 80/443; frps uses 7000 for agent control and 8443 for browser passthrough.
Keep PostgreSQL, the frps admin API and authz callbacks private. Opening their
host ports publicly is not a troubleshooting step.

The bundled image initializes new Caddy storage directories with root ownership
and mode 0700. Rebuilding does not repair permissions in existing volumes; review
the [storage boundary](../deploy/images/caddy/README.md#storage-permissions) before
backup or restoration. Preserve existing certificate state and an independent
management path during that maintenance.

There are three certificate lifecycles:

| Connection                     | Certificate owner                                                                                                              |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| Browser/agent to console HTTPS | The bundled Caddy, or the existing external reverse proxy selected during initialization.                                      |
| Agent to relay control         | The deployment's relay authority and protected host operations. Runtime containers do not hold the CA signing key.             |
| Browser to router GUI          | Per-device public certificate issuance, device-local key and verified native application. The relay does not decrypt this TLS. |

An existing reverse proxy can manage the console's certificate and renewal. It
does not replace relay trust or a router's GUI certificate.

## Initialize a fresh stack

Use a reviewed source revision with successful required CI, retaining that source
checkout for image builds. The [quickstart](../deploy/QUICKSTART.md) contains the
Docker-only build/initializer example and host ownership details. With the built
CLI available, a fresh external-proxy deployment can be prepared as follows:

```sh
sudo ./nethub init \
  --source-directory /srv/nethub \
  --directory /srv/nethub-deployment \
  --backup-directory /protected/nethub-backup \
  --console-host console.example.com \
  --device-domain router.example.com \
  --expected-address 203.0.113.10 \
  --proxy-mode external
```

Replace the documentation names/address and choose protected existing parent
directories. Initialization generates service-separated secrets, verifies the
backup and requires its printed acknowledgement. It does not start services or
change existing listeners. For a bundled Caddy deployment, use the default proxy
mode instead. `--offline` is isolated preparation, not verified public readiness.

External mode publishes only loopback HTTP origins. Install the generated example
in the existing host proxy and retain its HTTPS certificate/renewal configuration;
NetHub does not activate it. Follow [external proxy routing](../deploy/external-proxy.md)
for exact Host, forwarded scheme/source headers, private-path denial and port
selection. Do not trust client-supplied forwarding headers or every private subnet.

After successful initialization, enter the generated directory:

```sh
docker compose build migrate postgres frps backup
docker compose up -d
docker compose run --rm admin-bootstrap --email admin@example.com
```

For bundled mode, also build the `caddy` target before starting the stack. In
external mode there is no Caddy service. Use the hidden password prompt and
retain local-password emergency administrator access
when adding OIDC or SAML providers. The bootstrap service creates the first admin;
it is not an account-reset tool. Migration must succeed before Web/authz starts.

If initialization was interrupted before acknowledgement, preserve its state and
use `init --resume` with the same directory and backup. It verifies the original
material rather than generating replacement keys. Never rerun initialization
over a confirmed deployment as an upgrade or repair procedure.

## Verify readiness

Run the built CLI as the operator with access to the protected bundle:

```sh
sudo ./nethub doctor --directory /srv/nethub-deployment \
  --expected-address 203.0.113.10
```

This checks initialization/secret ownership, checksums, independent local backup
coverage, relay certificate identity/validity and optional DNS expectations.
It does not establish public port/TLS reachability, runtime database grants,
relay/authz health or scheduled database backups. Those omissions are printed;
do not treat exit zero as complete deployment acceptance.

The `--public-tls` option additionally checks the console
hostname from the initialized manifest on TCP 443, using the operating system's
normal CA store and hostname verification. It sends no HTTP request, cookie or
credential, ignores HTTP proxy environment settings and has a bounded TLS
handshake. The output includes whole days remaining; fewer than 30 days returns
a failure with a reminder to check the reverse proxy's renewal configuration.
NetHub does not take over the reverse proxy's certificate issuance or renewal.

```sh
sudo ./nethub doctor --directory /srv/nethub-deployment --public-tls
```

This is a probe from the machine running the command, not an independent
external-network witness. It neither proves external TCP 443/7000/8443
reachability nor validates HTTP routing, cookies, ACME provenance or every
reverse proxy address. It uses system trust; there is no insecure/private-CA
override flag. Runtime container separation, frps/authz loopback and recent
database backup have separate modes below. Agreement with a formally published
appliance package remains an unfinished W7-3 requirement.

For independent TCP observations, explicitly opt in to Check-Host:

```sh
./nethub doctor --external-tcp-check-host --expected-address 203.0.113.10
```

Replace the documentation address with the actual public ingress IP. This sends
only that IP and ports 443/7000/8443 to the external provider; its report may be
public. The [provider API](https://check-host.net/about/api) supplies three
observers per port. Every observer must report a connection to the expected IP;
wrong, incomplete, stale or unavailable results fail without partial success.
Submissions are not retried automatically, and the check stops after 45 seconds.
Run this mode separately from the initialized DNS, TLS, container and database
checks. It proves TCP connectivity from those observers, not certificate or
application health, successful device admission or every mobile network.
The implementation's mocked protocol tests do not replace a real owned-public
positive and closed-port drill, which remains pending.

The separate database metadata mode uses only the Web-role password:

```sh
docker compose exec -T nethub-web /nethub doctor --database-roles \
  --password-file /run/secrets/pg_nethub_web --sslmode disable
```

The generated stack uses an isolated database network; keep normal database TLS
verification for external databases. This mode requires the actual Web session
identity, checks Web/authz role flags and memberships, forced device RLS, schema
creation and Web identity/credential privileges in a read-only snapshot. It does
not test privileges by trying forbidden writes or reading credentials. It emits
a fixed repair suggestion rather than database diagnostics. Existing permitted
label/revocation updates are distinct from immutable device identity. A passing
database snapshot does not prove the running containers' mounts or ongoing
security after a later role change. Audit-chain checking is a separate mode.
Genuine SQL and compiled-command checks passed in the scoped W7 doctor
checkpoint. These results do not establish external reachability or restoration.

The Linux Docker host also has a read-only container mode:

```sh
sudo ./nethub doctor --runtime-containers \
  --directory /srv/nethub-deployment --project nethub
```

Use the actual existing Compose project and an absolute protected deployment
directory. If a separately reviewed protected override is part of that project,
select it explicitly with `--compose-file /protected/override.yml`. The command
uses the local Docker socket, requires root and never starts, stops, reloads or
executes inside a service. It first verifies the protected bundle and existing
authz/frps binding, then checks the running Web identity/image, exact command,
unchanged image environment, nonroot user, health, restricted capabilities,
read-only root, no host/shared process/IPC/UTS/user namespace overrides, no device mappings,
configured networks and private publication. Web must mount only
its read-only secret directory, containing exactly its database password and
provider-encryption key. Extra mounts/files or environment overrides are refused.
The full mode also checks the healthy backup worker's nonroot image, bounded
command, exact health probe, private runtime tmpfs, dedicated secret directory
and owned local archive volume. Container/image and authz/frps configuration are
rechecked before success.

This is an observation of the reviewed running layout, not attestation of an
arbitrary compromised image or a continuous policy enforcer. It does not replace
the database metadata mode, prove actual hook traffic or verify public ports,
recent dumps or published version agreement. Non-Linux hosts refuse this mode.
Genuine Docker and compiled-command checks passed in the scoped W7 doctor
checkpoint; the backup-worker extension passed the separate
[backup service checkpoint](../deploy/validation-database-backups.md).

The relay mode checks the Web/authz/frps prerequisites independently of backup
liveness, then
tests its actual loopback TLS Login hook path:

```sh
sudo ./nethub doctor --relay-hook \
  --directory /srv/nethub-deployment --project nethub
```

It uses the deployment's public relay CA and configured server name, submits one
invalid claim without a token/device secret/proxy, and requires the exact expected
denial from the configured Login hook. A TLS socket or a generic authentication
failure alone does not pass. The returned running frp version must match the
binary's protocol pin. The probe is bounded and does not retry automatically.
Failures point to TLS trust or `httpPlugins` connectivity without printing
dependency responses. It creates a deliberate denied-login log event, not an
enrollment, access grant, audit mutation or proxy. Actual isolated acceptance
also checked unchanged database row counts, an unavailable authz hook and
owned-service recovery. See [probe scope](../server/internal/relayprobe/README.md).

Add `--published-appliance` to compare the running relay's reported frp version
with the FreeBSD 15 amd64 `os-nethub-agent` entry in the official package feed.
This uses public HTTPS, pins the repository signing key and verifies the release
report's signature. A missing package version record, an invalid signature or a
version mismatch fails the check. The command checks the signed release
metadata and the actual relay Login rejection path. Public device admission and
router installation require their own checks.

Verify recent archive contents separately inside the existing backup worker:

```sh
docker compose exec -T backup /nethub doctor --recent-backup \
  --backup-directory /var/lib/nethub-backups \
  --password-file /run/secrets/pg_nethub_backup --sslmode disable
```

This derives the retained deployment identity through a read-only backup-role
connection and hashes the complete latest archive. It refuses an overdue or
failed latest attempt even when an older good archive remains. It does not
restore data or prove off-host custody. See [backup operation and limits](../deploy/database-backups.md).

For linked audit history, use the separate [read-only audit mode](../deploy/audit-chain.md)
inside the existing Web container. It verifies a database snapshot without
running initialization, migrations or repair; it does not replace the other
readiness checks or the remaining W7 requirements.

Verify console HTTPS with normal CA/hostname checking, local-admin login, logout
and secure cookies. Public `/healthz` and relay hooks must be denied. On the
approved test router, verify enrollment, a current certificate application report,
explicit Open and authenticated GUI access through the assigned hostname. A
green inventory row or installation report is not proof of that external path.

## Availability and revocation

Authz is a single point of failure for remote access. Generated callbacks include
Ping. The current development candidate uses a nominal one-second heartbeat and
three-second client/server timeout. Existing agents and bundles retain their old
timing until a coordinated upgrade. Authz outage, restart or shorter stalls can
cut existing tunnels; recovery is not guaranteed on a suspended host.
Keep host/router access that does not depend on this tunnel before maintenance.

Ping uses memory denials/floors refreshed every second within a shared one-second
read budget. Known denials remain monotonic, but admission authority expires
2.5 seconds after the read starts: database failure cannot retain unlimited
permission through an old snapshot. Stale state refuses Ping and a failed
freshness self-check stops authz. New admission still checks current SQL.
Source-IP grants last 30 minutes and renew only on explicit Open;
inventory polling and router traffic do not extend them. The router keeps its own
authentication. See [availability semantics](../deploy/revocation-and-heartbeats.md)
and the [installed measurements](../deploy/validation-native-w5-heartbeat.md).
The [current five-second measurements](w5-revocation-deadline.md) distinguish
accepted native/public samples from the remaining mobile, fleet and fault gates.

## Upgrade and credential handling

There is no general validated production upgrade procedure yet. Pin the accepted
source, image identities, schema and agent versions. Preserve the original bundle,
authority/secret backups and database state before a reviewed change. Version-1/2
bundles are refused; do not attach existing data to a fresh bundle or delete old
volumes to make migration pass. Existing volumes do not repeat database bootstrap.

Callback publication and Ping adoption require a coordinated Compose/frps change;
replacing only Web/authz does not enable them. Relay authority changes require the
[protected operation procedure](../deploy/relay-authority-operations.md), not a
manual CA-file substitution. Preserve overlap and offline-device recovery paths.

For an older 10/30-second deployment, upgrade client timing while retaining the
longer server timeout, then shorten the server timeout after participating agents
are ready. Rollback must widen the server timeout before reverting clients.
Follow the [coordinated order and remaining compatibility checks](w5-revocation-deadline.md#existing-development-deployments);
changing only the server does not establish the target for an old or offline fleet.

Preserve Web's `secrets_key` with the secret backup: it protects stored provider
credentials, SAML signing identities and flow state. Changing it is not a password
reset. Use the [device rotation operation](../deploy/device-rotation.md) for an
enrolled device. Deployment-wide frp-token replacement has a separate
[host incident procedure](../deploy/shared-relay-token-rotation.md), including
independent management before tunnel interruption and manual offline recovery.
Its host and online native recovery have [isolated acceptance](../deploy/validation-shared-token.md);
public/operator and complete restoration gates remain open. Neither procedure is an ad hoc
database credential update.

### Install or upgrade the OPNsense agent

Use the [KazuhaHub signed package feed](https://kazuhahub.github.io/OPNsense-repo/)
on an OPNsense 26.7 amd64 appliance. Configure the feed and verify its package
repository trust anchor using the feed's instructions. Check the offered
package before installation:

```sh
pkg update -r kazuhahub
pkg rquery -r kazuhahub '%n %v %q' os-nethub-agent
```

After the query returns the intended version for FreeBSD 15 amd64, install and
verify what is installed:

```sh
pkg install -r kazuhahub os-nethub-agent
pkg query '%n %v %q' os-nethub-agent
```

Enroll from **Services → NetHub Agent** with the console HTTPS address and
a one-time token issued by the Web console. Keep a separate way to reach the router and verify that the console
reports the enrolled device online.

For an upgrade, first save an encrypted OPNsense configuration backup and
retain the previous signed package snapshot and its release checksums. From
0.0.19, schedule a maintenance window and keep independent router access.
The installed 0.0.19 hook stops the tunnel before the incoming files are in
place. After the upgrade, confirm the device is online and check its NetHub
Agent status locally.

If a rollback is required, use the prior signed snapshot in a separate local
pkg repository and verify its catalog with the trusted repository key. Query
the exact old version in that repository before explicitly installing it.
Then verify that the original enrollment and tunnel work. A current public
catalog can offer only the newer package even when the previous signed
archive remains downloadable. Keep the prior snapshot before changing the
router.

## Backup and restore boundary

The initializer's checksum-verified backup is a protected local copy of the
deployment secrets and initial authority state. It is not a database backup or
proof of off-host durability. Runtime authority/leaf state can advance separately;
preserve the current state and protected operation receipts as well as the
immutable initialization backup. An old backup must not silently replace a newer
authority or operation journal.

The [database backup service](../deploy/database-backups.md) implements scheduled
restricted-role `pg_dump`, retention, worker health and a full-hash recent-archive
doctor. The [container checkpoint](../deploy/validation-database-backups.md) passed.
A separate [hosted recovery checkpoint](../deploy/validation-clean-host-restore.md)
restored matching current keys, the complete database and six services, then
verified the retained native and witness routes. It does not complete a fresh
public-VPS/operator drill, protected off-host custody or the full host restoration
scope. No general production restore command is accepted here.

With GUI certificate automation enabled, recovery must also preserve the
protected host's ACME account, issuer/HTTP-01 policies and namespaces, installed
helper and reviewed systemd configuration. These live outside the six-container
database restore. The [custody inventory](../deploy/database-backups.md#custody-and-restoration)
and [account namespace procedure](../server/internal/guiacme/PROVISIONING.md)
describe that boundary. The later
[protected-host drill](../deploy/validation-protected-host-cold-recovery.md)
passed isolated restoration with the same original issuance request, native
application and verified route. That is independent evidence beyond the
six-service checkpoint; it does not establish a public operator restore
procedure or durable encrypted off-host custody.

## Troubleshooting

| Symptom                                      | Check and action                                                                                                                                                                                                  |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Initialization or doctor rejects a file      | Preserve the directory and diagnostic. Correct the named ownership/backup problem; do not relax private modes or regenerate keys.                                                                                 |
| Web/authz stays unhealthy                    | Inspect the owned service's health and migration result with `docker compose ps` and scoped logs. Keep secrets and raw diagnostics private; do not publish a whole bundle.                                        |
| Console works, router does not               | Check current relay observation, device certificate state and explicit Open. After changing networks, renew Open; different IPv4/IPv6 or shared-NAT sources can affect the grant.                                 |
| Tunnel drops during authz maintenance        | Restore the approved authz configuration and private callback path; verify health before reconnect testing. Do not expose the hook/admin API publicly.                                                            |
| SSO fails                                    | Retain local-admin recovery. Check the provider's enabled state, exact callback/entity addresses, trusted metadata or OIDC discovery and invitation restriction. Do not log assertions, tokens or client secrets. |
| Existing deployment needs an upgrade/restore | Preserve its files, volumes and receipts. Use the reviewed operation-specific procedure; a fresh `init` is not an in-place migration.                                                                             |

The remaining release, friend-from-zero deployment, restore, faulty-version and
public/mobile acceptance requirements remain in [PLAN](PLAN.md). They are not
closed by publishing this guide.
