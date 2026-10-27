# Deployment and operations

NetHub is pre-alpha; there is no signed production release. Use a dedicated Linux
host and retain an independent management path to the host and router. The
[handoff](HANDOFF_PROMPT.md) records accepted source revisions and measurements.
W5-W7, public-provider acceptance and the complete backup/restore drill remain
open. This guide records current commands and operational boundaries, not a
claim that those remaining acceptance items have passed.

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
docker compose build migrate postgres frps
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

The in-progress W7-3 `--public-tls` option additionally checks the console
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
override flag. Runtime container separation, frps/authz loopback, recent database
backup and version agreement remain separate unfinished W7-3 checks. Hosted
acceptance for this new option is still pending.

The separate in-progress database metadata mode uses only the Web-role password:

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
The new genuine SQL and compiled-command acceptance cases are not yet executed
at the final hosted source revision.

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
Ping, and the agent uses a 10-second heartbeat/30-second timeout. Authz outage or
restart can cut existing tunnels; recovery is not guaranteed on a suspended host.
Keep host/router access that does not depend on this tunnel before maintenance.

Ping uses a revocation snapshot refreshed every five seconds. New admission still
checks SQL, while database failure can delay a newly revoked ID entering the
snapshot. Source-IP grants last 30 minutes and renew only on explicit Open;
inventory polling and router traffic do not extend them. The router keeps its own
authentication. See [availability semantics](../deploy/revocation-and-heartbeats.md)
and the [installed measurements](../deploy/validation-native-w5-heartbeat.md).

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

Preserve Web's `secrets_key` with the secret backup: it protects stored provider
credentials, SAML signing identities and flow state. Changing it is not a password
reset. Device credential rotation, deployment frp-token rotation and their
offline-device recovery procedure remain W7 work; do not substitute a schema
example or ad hoc database update for those operations.

## Backup and restore boundary

The initializer's checksum-verified backup is a protected local copy of the
deployment secrets and initial authority state. It is not a database backup or
proof of off-host durability. Runtime authority/leaf state can advance separately;
preserve the current state and protected operation receipts as well as the
immutable initialization backup. An old backup must not silently replace a newer
authority or operation journal.

W7 still requires scheduled `pg_dump` with the restricted backup role, retention,
protected off-host storage and a full clean-host restore drill. That drill must
restore the matching database and keys, preserve account/device authority and
verify an already enrolled device reconnects. No complete restoration command is
documented as accepted here because that operator drill has not passed. Existing
local-copy, transaction or process-recovery tests do not replace it.

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
