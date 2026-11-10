# NetHub control plane

The Go control plane provides the console, enrollment, device identity and relay
admission for remote router GUI access. It has no general command, firewall or
configuration-push API. The OPNsense adapter owns its local settings, tunnel and
verified GUI certificate application; that bounded path can reload the GUI.
The relay passes GUI TLS through without decrypting it.

NetHub is pre-alpha. Scoped server, native and public-certificate checks have
passed, including isolated protected-host recovery. Public/operator W5-W7,
durable off-host custody, disclosure and formal release remain separate gates.
 The [handoff](../docs/HANDOFF_PROMPT.md) binds acceptance
to sources and environments; the [plan](../docs/PLAN.md) tracks remaining work.
Changed sources and rebuilt clients need their own applicable checks.

## Technology stack

- Go 1.26.10 builds one nethub binary. The module is
  github.com/KazuhaHub/nethub/server; Go 1.26.0 is its language floor.
- React, TypeScript and Vite build the embedded SPA, using shadcn/ui and native
  dialog. Generated web/dist is not committed.
- PostgreSQL 16 stores accounts, devices, jobs and operation/audit history.
- Bundled Caddy or an administrator-managed proxy owns console HTTPS.
- Unmodified frp 0.71.1 supplies frps and the separately packaged frpc; pins agree.
- Python 3.13/PHP implement the OPNsense adapter. Python also supports isolated
  acceptance tooling; it is not the control-plane runtime.

Deployment targets one Docker Compose host, with no Kubernetes target for v1.

## Runtime roles and the process split

| Command | Boundary |
| --- | --- |
| web | Console API/SPA, sessions, administration, source grants, audit and traffic. |
| authz | Device lifecycle/certificate/trust APIs, relay hooks and observations. |
| migrate | One-shot schema migration using the owner role. |
| admin-bootstrap | One-time initial local administrator; preserves break-glass access. |
| init | New deployment files, independent secret backup and acknowledgement; refuses overwrite. |
| doctor | Explicit file/DNS, TLS, role, container, hook, archive and audit checks. |
| backup | Restricted archive production, daily worker and health checks. |
| certificates, relay-token | Protected host operations with separate lease, custody and recovery requirements. |

Web never mounts the claim key or frps administration credentials. Its database
role cannot create a device or rewrite its identity/claim. Authz consumes one-use
tokens, derives ownership from them, and signs/validates claims. Device HTTPS and
private relay callbacks have separate listeners. See the
[console API](../docs/console-api.md), [device runtime](internal/device/README.md)
and [deployment guide](../docs/deployment.md).

A compromised Web process can exercise console authority: issue enrollment
tokens, revoke devices, grant source access, administer users/providers and decrypt
its provider secrets. It cannot sign a claim for an existing assignment.
This separation does not confine compromised root, Docker or authz. See the
[threat model](../docs/threat-model.md).

## Relay admission and availability

Generated frps configuration subscribes to Login, NewProxy, NewUserConn and Ping.
Replacing a binary alone does not migrate an older callback list.

Login/proxy admission matches signed canonical claims against current device
state. NewUserConn additionally requires an exact source-IP grant from an
authorized console Open click. Open grants 30 minutes; traffic and inventory
polling do not renew it. The gate identifies network position, not a person:
shared NAT, IPv4/IPv6 differences and existing streams remain limitations.
Router authentication and normal GUI certificate verification remain required.

Ping checks an initialized in-memory revocation/rotated-claim snapshot, refreshed
every five seconds. Ordinary database failure retains the last good state; new
connection admission still checks SQL. Unresponsive refresh or failed self-check
stops authz rather than leaving a partially live API.

The 10-second heartbeat and 30-second timeout make authz an availability dependency
for existing tunnels. Restart/outage interrupts access; suspended processes and
stale snapshots can delay observations. There is no instantaneous browser-stream
cutoff guarantee. Display polling runs every five seconds; anomaly confirmation
separately requires three 15-second observations. See
[hooks](internal/relayhook/README.md),
[availability](../deploy/revocation-and-heartbeats.md),
[anomalies](../deploy/relay-anomalies.md) and the
[installed timing discrepancy](../deploy/validation-native-w5-heartbeat.md).

## Ports

- Public TCP 80/443: reverse proxy and reviewed HTTP-01 device-certificate route.
- Public TCP 7000: relay TLS control; 8443: relayed device GUI TLS.
- PostgreSQL and application HTTP origins remain private. Generated hook/admin
  publications bind only to host loopback for host-network frps; authz also
  validates its configured peer. These are not public APIs.

[External-proxy mode](../deploy/external-proxy.md) must preserve reviewed routing
and forwarding policy. GUI issuance additionally requires a separately provisioned
protected host. Ordinary init does not create its ACME account, accept CA terms
or install issuer/helper/timers.

## Users, roles and sign-in

Each v1 instance selects one tenant. Administrators manage accounts, invitations,
providers and tenant devices. Members operate their own devices. The store
rechecks live role/ownership; disabled users cannot continue using their sessions.

Local passwords use bounded Argon2id. Server-side sessions have 30-minute idle
and 12-hour absolute limits, secure HttpOnly cookies, Origin/CSRF checks and
process-local throttling. Explicit background-read routes can use passive
validation without extending activity. See [authentication](internal/auth/README.md).

NetHub directly imports authcore OIDC/SAML at development revision
`c1447857d71b` (`v0.6.3-0.20261106113728-c1447857d71b`), not a new formal
release. The reviewed interim SAML parser replacement is also pinned in
`go.mod`; see [the dependency record](../deploy/saml-dependency-security.md).
Authcore owns protocol verification. NetHub owns browser/replay persistence,
invitation/account admission, outbound network policy, roles, encryption and audit.
Reusable protocol gaps belong in authcore with their own tests; do not copy it.

OIDC binds issuer/subject using Authorization Code/PKCE, state and nonce.
SAML binds an IdP/SP-scoped persistent NameID with signed protocol messages and
durable replay checks. Neither binds by email alone or permits self-registration.
An unlinked identity requires the valid invitation-bound flow and matching verified
attributes; a matching email without the invitation cannot claim it.
See [OIDC admission](../deploy/oidc-login.md) and [SAML admission](../deploy/saml-login.md).

The [two-Dex](../deploy/validation-two-dex.md) and
[Keycloak](../deploy/validation-keycloak-saml.md) records have scoped deployed
acceptance. Public-provider/operator W6 remains open. Console SSO does not
replace router GUI authentication.

## Data model

The [embedded migrations](internal/store/migrations/) and actual-role tests are
authoritative SQL. DESIGN includes architecture and historical sketches.
Core account/device tables are extended by grants, certificate jobs/generations,
trust/authority history, rotations, provider flows/replays and traffic counters.

Tenant-scoped tables use forced RLS. Member isolation also requires live actor
and owner checks; tenant RLS does not constrain a compromised Web process beyond
its granted SQL authority. Global trust data has separate RLS/function boundaries.
Revocation is one-way; an old revoked identity cannot simply be re-enabled.

Login roles are nethub_owner for migrations, nethub_web, nethub_authz and restricted
read-only nethub_backup. Protected issuer work uses a narrow no-login role through
the host adapter. Bootstrap superuser access is separate from runtime services.
Per-service mounts separate credentials; readiness and genuine SQL tests verify
required privileges and refusals.

Audit appends serialize the tenant chain and commit with their mutations.
The [checker](../deploy/audit-chain.md) detects consistency failures, not privileged
database rewriting. See [store boundaries](internal/store/README.md),
[issuer role](internal/store/GUI_ISSUER_ROLE.md) and
[backup operations](../deploy/database-backups.md).

## Directory layout

The CLI is in cmd/nethub. Console policy uses internal/web, auth, sso and
providersecret; device/admission code uses device, claim, protocol, relayhook and
relaystate. Certificate, trust, host-operation and backup packages have their own
component guides. Store migrations own the schema, web the SPA and tests the
isolated deployment/IdP/recovery harnesses. The adapter lives in
[agents/opnsense](../agents/opnsense/README.md).

## Development and validation

Run these commands from this directory:

```sh
export GOWORK=off
go test ./...
go vet ./...
go mod verify
```

Genuine PostgreSQL tests require the isolated Docker harness in the
[store guide](internal/store/README.md); local Go success can include skipped
integration cases. CI also runs compiled processes, deployment, browsers and
independent IdPs. Native installation uses a separate exact-source workflow.

The [isolated recovery integration](../deploy/validation-clean-host-restore.md)
restored current keys, the full database and six services, then recovered retained
native/witness TLS routes without requested client restart, Rotate or enrollment.
The [protected-host recovery](../deploy/validation-protected-host-cold-recovery.md)
also restored the registered issuer account, issuance policy and publication state.
These isolated checks do not prove public operator recovery or durable encrypted
off-host custody. Signed packaging, canary/faulty-version,
friend-from-zero deployment and remaining W5-W7 checks are still required.
