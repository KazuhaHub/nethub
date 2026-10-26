# server/ — NetHub control plane

This directory contains the NetHub control plane: the service
designed to let a user open a remote OPNsense Web UI that sits behind CGNAT or
a dynamic IP, without port forwarding, and without the control plane itself
ever reading the device's `config.xml`, changing firewall rules, or restarting
services on the device. That boundary is deliberate — see the top-level
[project README](../README.md) and [`docs/DESIGN.md`](../docs/DESIGN.md) for
the reasoning.

> **Status: pre-alpha, no production release.** Web, authz, enrollment and console
> account administration are implemented. The Go module directly imports
> authcore's OIDC/SAML packages at `ee68d852d973` through a development
> pseudo-version. The adapters delegate protocol processing and enforce console
> policy; identity and invitation admission remain in NetHub. Actual PostgreSQL
> and strict-CSP browser checks cover the applicable boundaries. Two deployed Dex
> issuers and the SAML backend/pages have accepted records; deployed signed SAML
> IdP and public-provider acceptance remain separate work. Native device evidence
> and the remaining W5-W7 requirements are tracked in the
> [handoff](../docs/HANDOFF_PROMPT.md), not implied by passing server tests.

The local [first-admin command](cmd/nethub/admin-bootstrap.md) is implemented with
hidden terminal entry or protected stdin, owner-role isolation, and atomic one-time
creation. The init wizard and its Compose bootstrap service pass real deployment
tests, including the combined clean-host public HTTPS/browser run. See
[deployment validation](../deploy/validation-w3.md) for evidence and scope.

The local [password/session service](internal/auth/README.md) and tenant-bound
PostgreSQL authentication store are implemented, with actual-role tests for
expiry, logout, account disable, and password-check races. The
[console API](internal/web/README.md) wires cookie/CSRF/Origin/proxy checks and
atomic audit for login, logout, and token issuance. The [React UI](web/README.md)
uses these routes and embeds its production build in Go. Isolated browser evidence
is in [UI validation](web/validation.md); real Compose and public browser evidence
is in [deployment validation](../deploy/validation-w3.md).

## Technology stack

- **Go 1.26.10** — pinned in `.go-version`, CI, and the Docker builder. The
  module's `go 1.26.0` line remains its language compatibility floor, not a
  deployment compiler recommendation. This uses the same toolchain line as the organisation's other Go
  repositories. The control plane is a **single binary, `nethub`**, with
  subcommands. Planned module path: `github.com/KazuhaHub/nethub/server`.
- **React + TypeScript + Vite** — the console is a single-page app whose
  source lives in `server/web/`. The build output is embedded into the binary
  with `go:embed`, so the console ships inside `nethub web`; the built `dist/`
  is not committed. The selected UI is shadcn/ui with native dialog.
- **PostgreSQL 16** — primary datastore, with row-level security and
  column-level grants doing real work (see [Data model](#data-model) below).
- **Caddy** — reverse proxy and TLS termination on port 443, in front of the
  control plane's HTTP surfaces.
- **frps** (upstream frp, not written here — see [`NOTICE`](../NOTICE)) — the
  relay. Pinned to frp 0.71.1 alongside the device-side frpc. It is configured
  with `bindPort = 7000` (the device control channel, TLS),
  `vhostHTTPSPort = 8443` and `subDomainHost` set, doing SNI passthrough to
  the device-side `frpc`. Its `httpPlugins` call back into `nethub authz` for
  `Login` and `NewProxy`, to validate a device's signed domain claim against
  the database before a proxy may register. `NewUserConn` is also listed, but
  only to collect data in Weekend 0; it is used for enforcement only if the
  owner approves DESIGN Q7. `Ping` is a further candidate op, tied to the
  unresolved question of how a device gets cut off (see the `nethub authz`
  notes below).
- Deployment is **`docker compose`** on a single host. There is no Kubernetes
  deployment target for v1. See [`deploy/README.md`](../deploy/README.md).

Not in this directory: the device side. The OPNsense agent stays Python 3.13
(`agentctl.py`) plus PHP/Phalcon MVC because OPNsense dictates it, and is
planned under [`agents/opnsense/`](../agents/opnsense/README.md). Python
appears in this project only as `agentctl.py` and the Weekend 0 `probe.py`;
the control plane has none.

## Runtime roles and the process split

One binary, two runtime roles, run as two containers. The split makes the
design's "a compromised console must not be able to hijack a device" goal
(DESIGN decision #4) concrete instead of a promise.

| Subcommand | Role |
|---|---|
| `nethub web` | The public console. |
| `nethub authz` | Device-facing and relay-facing. |
| `nethub migrate` | One-shot migrations, run as the owner role `nethub_owner`, which no runtime process uses. |
| `nethub init` | First-run setup wizard (secrets, first admin). See [`deploy/README.md`](../deploy/README.md). |
| `nethub doctor` | Preflight checks. See [`deploy/README.md`](../deploy/README.md). |

**`nethub web`** serves the SPA and a JSON API under `/api/v1/console/...`.
The planned endpoints, conventions and error codes are drafted in
[`docs/console-api.md`](../docs/console-api.md).

- Features: local and OIDC sign-in; users and invites; OIDC providers; device
  list; enroll tokens; revoke; audit view.
- Postgres role: `nethub_web`.
- It never holds the claim signing key or the frps admin credentials.
- Column-level grants: it may INSERT `enroll_tokens` (recommended: by column
  only, `tenant_id`, `token_hash` and `created_by_user_id`, so `created_at` and
  `expires_at` can only take their database defaults), and UPDATE
  `devices.revoked`, `revoked_at`, `revoked_by_user_id` and the display
  `label`. It may **not** INSERT into `devices`, and may not write
  `devices.subdomain`, the claim field (`domain_claim_issued_at`),
  `device_secret_hash`, or change `owner_user_id`, `tenant_id` or
  `cluster_hint`.

**`nethub authz`** is what devices and the relay talk to.

- Device API: `/api/v1/devices/{enroll,rotate,unenroll,status}`; Caddy routes
  these from port 443 to authz.
- The frps `httpPlugins` handler, reachable on the internal docker network
  only.
- A poller of the frps admin API (internal only), planned to check active
  proxies every 15 s and to treat three consecutive anomalies (about 45 s) as
  the point at which a device should be cut off, with both the verdict and the
  outcome written to `audit_log`. A manual "confirmed stolen, cut now" bypass
  is also planned: `web` can only write the revocation flag, and `authz`
  carries out the cut.
  **The poller only detects; the cut-off mechanism is unresolved.** In the frp
  0.71.0 source the admin API can list clients and proxies and clear *offline*
  proxies, but it has no endpoint that disconnects an online client or proxy,
  so authz cannot cut a connected device through it. DESIGN §5 lists the
  candidate mechanisms, none of them measured yet, and Weekend 0 is meant to
  test them against a real `frps` binary before any security-model code is
  written:
  - reject `Ping` (the proposed main mechanism), which needs explicit
    heartbeat settings on both `frpc` and `frps` because frp's defaults leave
    them off;
  - reject `NewUserConn` for the revoked device (a supplement: it blocks new
    browser connections, it does not disconnect anything);
  - restart `frps` (a manual last resort that drops every device);
  - patch `frps` to add a disconnect endpoint (not recommended: it would mean
    maintaining a fork, against the same-version, unmodified rule of DESIGN
    decision #19).

  The `Ping` route has an availability cost worth stating. In the frp 0.71.0
  source, a plugin call that errors (connection refused, a non-200 status, an
  unparseable reply) is treated as a rejection, so a subscribed `Ping` is
  fail-closed like `Login` and `NewProxy`. If authz crashes, restarts or
  returns 500, every live tunnel is cut at its next `Ping`, within about one
  heartbeat interval. If authz hangs, they are cut when `heartbeatTimeout`
  expires, because `frps` puts no timeout on plugin calls. authz then becomes
  the single point of failure for all remote access, not only for new
  connections. If this route is adopted, three things are mandatory:
  - the `Ping` handler answers from in-memory revocation state, with no
    database call;
  - strict internal timeouts on the plugin handlers;
  - authz exits when its self-check fails, so the container restart policy
    applies.

  These shorten recovery but cannot prevent the cut. Weekend 0 item ⑥
  measures the cost. Until those results exist, nothing here promises a
  cut-off mechanism or a cut-off latency (DESIGN §5).
- It holds the claim signing key (a file mounted only into this container), the
  frps admin credentials, and the frps auth token that it hands to devices in
  the enroll response. Postgres role: `nethub_authz`.
- It consumes enroll tokens, creates device rows, and assigns each device's
  subdomain. The subdomain is random and chosen by the server; neither the
  client nor `web` can choose it. A new device's `owner_user_id` comes from the
  `created_by_user_id` of the enroll token it consumed.
- It signs the domain claims: HMAC-SHA256 over a canonical payload
  `{device_id, subdomain, tenant_id, issued_at, key_id}`. `key_id` allows key
  rotation. Only authz signs and verifies, so a symmetric key is enough.
- Looking up an enroll token happens before the tenant is known, so it goes
  through one narrow `SECURITY DEFINER` function (for example
  `consume_enroll_token(token_hash)`).

**What the split does and does not buy** (stated honestly):

- A compromised `web` process **can**:
  - create enroll tokens — and so enroll a *new* device under a *new*
    subdomain, which is not a hijack of an existing device;
  - revoke devices (an availability attack);
  - read device metadata and the audit log;
  - create enroll tokens of any lifetime, if it holds a whole-table INSERT on
    `enroll_tokens`, which would make the 15-minute expiry meaningless once
    `web` is cleaned up. Hence the recommended per-column INSERT grant, with
    `created_at` and `expires_at` taken from database defaults and
    `consume_enroll_token` enforcing a maximum lifetime on the server side;
  - if the DESIGN Q7 source-IP gate lands, register any IP for any device and
    so make the gate pointless: the "open" click is only visible to `web`, so
    the gate is never stronger than the console;
  - and what it already owns: inviting and creating users, changing OIDC
    provider settings, and decrypting OIDC client secrets (it holds
    `NETHUB_SECRETS_KEY`) — in short, the whole console.
- It **cannot** obtain a valid claim for an existing subdomain or change who
  owns a subdomain. That is the property decision #4 needs.
- A compromised `authz` means the relay identity layer is compromised. The
  trust point is the same as in earlier drafts; the difference is that its
  surface is small and explicit — no console, no user sessions, no access to
  the user tables.

## Ports

- **Public:** 443 (Caddy: console and device enroll API), 7000 (frps
  `bindPort`: device control channel, TLS), 8443 (frps `vhostHTTPSPort`:
  browser to device, SNI passthrough).
- **Internal only** (docker network, never published): the frps admin API
  that authz polls, the authz `httpPlugins` endpoint, and Postgres.

## Directory layout (planned)

Planned; finalized when code lands.

```
server/
  go.mod
  cmd/nethub/          subcommands: web | authz | migrate | init | doctor
  internal/
    web/               console JSON API + SPA serving
    authz/             device API, frps httpPlugins handler, frps admin poller
    claim/             domain-claim format, signing, verification
    auth/              local password (argon2id), sessions, CSRF, login throttling
    sso/               OIDC/SAML authcore adapters and outbound-network policy
    store/             Postgres access, roles, migrations
    audit/             audit_log writer + hash chain
    clientip/          trusted-proxy client IP resolution
    frps/              frps admin API client
  web/                 React + TS + Vite source
```

Application-level tests are expected to cover the API, the domain-claim
verification path, and the database-level checks described under
[Data model](#data-model). `nethub init` and `nethub doctor` are subcommands
of this same binary, not separate tools.

## Users, roles and sign-in (v1)

- **First admin.** `nethub init` creates the first admin with a local password
  (argon2id). This is the break-glass account; local password login stays
  available even once OIDC is configured.
- **Roles.** `admin`: users, invites, OIDC providers, all devices in the
  tenant, audit. `member`: own devices only (create an enroll token, open,
  revoke) and own audit entries. Member device queries also filter on
  `owner_user_id`.
- **Single tenant.** Each instance has exactly one tenant in v1, and
  `app.tenant_id` is set to it on every connection.
- **Invites.** An admin invites by email plus role. The invite is a one-time
  link token; only its hash is stored, and it expires (for example after
  72 h). The invitee binds by setting a password, or by signing in with OIDC
  **starting from the invite link** (see the next item).
- **OIDC.** Multiple providers, configured by an admin in the console.
  Authorization Code with PKCE, plus state and nonce; ID tokens are verified
  with `github.com/coreos/go-oidc/v3` using issuer discovery. An identity is
  bound by `(issuer, subject)`, **never by email alone**. A sign-in succeeds
  in exactly two cases:
  1. `(issuer, subject)` is already linked to a user; or
  2. the invitee starts the OIDC flow **from the invite link**. The server
     binds that invite into the flow's `state` (recorded server-side, so the
     browser does not get to say which invite it is claiming). At the callback
     the identity is linked and the invite marked used only if **all three**
     hold: the invite token is valid (unexpired and unused), the ID token has
     `email_verified=true`, and its email matches the invite's email.

  An OIDC sign-in that did not come from an invite link is rejected, even if
  its email happens to match a pending invite. For example, signing in through
  a second IdP that reports the same email, without the invite link, does not
  claim the invite. The reason is that `email_verified` cannot be trusted
  across IdPs (the admin of a self-hosted Dex or Keycloak can mark any email
  as verified), so what authorizes the claim is the one-time invite token, with
  the email as an extra check (DESIGN decision #22 and §13 scenario #13). An
  admin may optionally restrict an invite to a single provider (for example a
  nullable `provider_id` on `invites`; to be settled with the migrations).
  There is no self sign-up and no JIT provisioning in v1. Provider client
  secrets are encrypted at rest with AES-256-GCM, using `NETHUB_SECRETS_KEY`,
  which `nethub init` generates and only `web` holds.
- **Disabled users.** A user with `disabled_at` set cannot sign in, and their
  sessions are revoked with it.
- **SAML** is included in v1, via `authcore/saml`, as a pure service
  provider.
- **Sessions.** A server-side `sessions` table. The cookie holds an opaque
  random token (HttpOnly, Secure, SameSite=Lax); only its hash is stored.
  Idle and absolute timeouts; sessions are revocable.
- **CSRF.** A per-session synchronizer token, sent in a custom header on every
  state-changing request.
- **Other hardening.** A strict Content-Security-Policy and no server-side
  templates. Login throttling is per IP and per account and lives in-process,
  so v1 assumes a single `web` instance.
- **Client IP.** Behind Caddy, `X-Forwarded-For` is honoured only from the
  configured trusted-proxy addresses; proxy headers arriving from an
  undeclared peer produce a loud warning. The resolved IP feeds login
  throttling and audit, and the same rule applies to the device API served by
  `authz`, which is also behind Caddy.
- **SSO does not protect the device GUI.** The OPNsense GUI behind the tunnel
  keeps its own login; the console's password, OIDC and sessions are not on
  that path. How to handle that exposure is an open question (DESIGN Q7).

## Shared auth code: authcore

Shared authentication code lives in `KazuhaHub/authcore` (Apache-2.0). NetHub
directly imports its `oidc` and `saml` packages for v1. The current verified
development pin is merge `ee68d852d973d83832dd6eaedd3700a7266e438c`, which includes
OIDC verification, signed SAML NameID qualifiers and RSA/ECDSA AuthnRequest
signing. It is not a new release tag.

Authcore owns protocol verification. NetHub owns persistent browser/replay state,
tenant/account admission, invitations, roles, cookies, outbound network policy,
credential encryption and audit. Login and proxy-IP policy remain in NetHub.
The [provider backend](../deploy/oidc-providers.md) implements administrator APIs.
The [OIDC callback backend](../deploy/oidc-login.md) implements durable browser
state and transactional identity/invitation admission. The
[two-Dex deployment](../deploy/validation-two-dex.md) and
[SAML backend/pages](../deploy/saml-console.md) have scoped acceptance records.
Deployed signed SAML IdP, public-provider and combined W6 acceptance remain open.
Optional `captcha`, `geoip` and later `passkey` integrations remain separate decisions.

## Data model

This is a summary of the core Postgres schema; the authoritative (and still
illustrative, not final SQL) version is in [`docs/DESIGN.md`](../docs/DESIGN.md)
§6. Nine tables anchor v1:

- **`tenants`** — the top-level isolation boundary; exactly one row per
  instance in v1. Every other table below carries a `tenant_id`.
- **`users`** — console accounts. `email` is unique per tenant;
  `password_hash` is nullable, for OIDC-only users; `role` is
  `'admin' | 'member'`; `disabled_at` marks a disabled user.
- **`user_identities`** — links a user to an external identity:
  `provider_id`, `issuer`, `subject`, `email_at_link`, `created_at`, with
  `UNIQUE (issuer, subject)`. Binding is by `(issuer, subject)` only.
- **`oidc_providers`** — admin-configured providers: `slug` (unique),
  `display_name`, `issuer_url`, `client_id`, `client_secret_enc`, `scopes`,
  `enabled`, `created_at`.
- **`invites`** — `email`, `role`, `token_hash` (unique), `created_by_user_id`,
  `created_at`, `expires_at`, `used_at`.
- **`sessions`** — `user_id`, `token_hash` (unique), `created_at`,
  `expires_at`, `last_seen_at`, `ip`, `user_agent`.
- **`devices`** — one row per enrolled device. It is designed to carry, from
  the first migration:
  - `platform` — e.g. `"opnsense"` (`NOT NULL`). Present from the start even
    though v1 only supports OPNsense, so the schema never has to be retrofitted
    for OpenWrt/VyOS later.
  - `capabilities` — what this device/agent combination can do (`NOT NULL`
    array; the v1 OPNsense agent declares only `remote.web`). The control plane
    gates features on it rather than branching on `platform`.
  - `owner_user_id` — the user this device belongs to.
  - `subdomain` (unique, random, server-generated) and
    `domain_claim_issued_at`: the ownership and claim material behind the dual
    "signed claim valid + matches the DB record" check performed in
    `httpPlugins`.
  - `device_secret_hash` (argon2id): the credential the device presents to the
    device API (`rotate`, `unenroll`, `status`). There is deliberately **no**
    per-device frps token hash: the frps auth token is one shared secret per
    deployment (DESIGN decision #21), only the first gate into `frps`, so a
    per-device hash of it would mean nothing. A device's identity is its signed
    claim (checked together with the DB record) plus its `device_secret`. If
    the shared token leaks, the remedy is to replace it and `rotate` the
    devices that are online (decision #18).
  - `hostname`, and `label`: a display name that can be edited in the console
    and takes part in no validation.
  - `platform_version`, `agent_version`, `agent_protocol_version`,
    `cluster_hint` (an optional CARP annotation, display only, also a reference
    signal for downgrading anomaly verdicts to alerts), `enrolled_at`,
    `last_seen_at`, and the revocation columns `revoked`, `revoked_at`,
    `revoked_by_user_id`.
- **`enroll_tokens`** — short-lived, single-use tokens that authorize one
  device's enrollment; the device presents one to the enroll endpoint served by
  `nethub authz` (see [`proto/README.md`](../proto/README.md)). Only the hash
  (`token_hash`, unique) is stored. `expires_at` defaults to `now()` plus 15
  minutes and `created_at` to `now()`; `web` cannot set either, and
  `consume_enroll_token` enforces a maximum lifetime on the server side.
- **`audit_log`** — an append-only record of security- and access-relevant
  events: manual actions, system actions (cut-offs, rotations, reconcile
  failures) and authentication events (sign-ins, identity binding, invites).
  Columns include `tenant_id`, `actor_type` (`'user' | 'system' | 'device'`),
  `actor_id`, `action`, `target_device_id`, `payload` (JSONB), `prev_hash` and
  `entry_hash` (the hash chain), and `created_at`. Both runtime processes
  append to it, so computing `prev_hash` has to be serialized (for example by
  taking a lock inside a function and reading the chain head); that detail is
  settled with the implementation.

**Row-level security.** Postgres `ENABLE` and `FORCE ROW LEVEL SECURITY` are set
on every tenant-scoped table (every table listed here except `tenants`, which
has no `tenant_id` column), so the policy applies to table owners too and a query that
forgets the tenant setting fails closed rather than leaking rows. Since v1 has
exactly one tenant per instance, this guards against a mis-set or missing
`app.tenant_id`, and means a future multi-tenant version needs no retrofit.
It is **not** what separates one `member` from another: isolation *within* the
tenant is an application-layer `owner_user_id` filter, applied centrally in
the `store` layer and covered by tests.

Because `FORCE` binds table owners too, the `SECURITY DEFINER` function that
looks up an enroll token before the tenant is known (`consume_enroll_token`)
has to be owned by a role with `BYPASSRLS` (for example `nethub_owner`, which no
runtime connection uses). It pins its `search_path`, returns only the minimum
fields, and has `EXECUTE` granted to `nethub_authz` alone. The details are
settled with the migrations.

**Postgres roles and column-level grants.** There are four roles, with grants
split to match the process split above. Separately, the official Postgres
image has a bootstrap superuser (`POSTGRES_PASSWORD`). Only the `postgres`
container uses it, for first initialisation; no runtime service connects with
it (DESIGN §6, decision #21).

- `nethub_owner`: runs migrations only (`nethub migrate`); no runtime process
  uses it.
- `nethub_web`: the console. INSERT on `enroll_tokens` and UPDATE on the
  `devices` revocation columns and `label`, as described under `nethub web`;
  no INSERT on `devices`. It manages the user, invite, session, OIDC-provider
  and identity tables. The design recommends granting its SELECT per column
  too, so it cannot read the hash columns.
- `nethub_authz`: devices and the relay. `EXECUTE` on `consume_enroll_token`,
  and SELECT, INSERT and UPDATE on `devices` (creating device rows, assigning
  subdomains, updating `last_seen_at`). It has no privileges on the user,
  invite, session, OIDC-provider or identity tables.
- `nethub_backup`: used by the `backup` service's `pg_dump` and by nothing
  else. `LOGIN` and `BYPASSRLS`, with read access to everything (for example
  the predefined role `pg_read_all_data`, which does not itself bypass RLS, so
  `BYPASSRLS` is granted separately) and no write privilege of any kind.
  A plain role cannot do this job: with `FORCE ROW LEVEL SECURITY` on every
  tenant-scoped table, `pg_dump` fails with an error for a connecting role that
  is neither a superuser nor `BYPASSRLS`, instead of writing an incomplete
  dump. This is a design so far; it has not been run (DESIGN §15). Its password
  lives only in the `backup` service's own secret directory (see
  [`deploy/README.md`](../deploy/README.md)).

Both runtime roles (`nethub_web` and `nethub_authz`) can only append to
`audit_log`. A test is planned that proves `nethub_web` cannot write device
identity columns or insert into `devices`. The SQL in DESIGN §6 is a sketch, not
final; the grants are fixed when the migrations are written.

One gap worth stating plainly: `nethub_web` can UPDATE `revoked`, so as
sketched it could also flip it back to `false` and reconnect a revoked device.
The design recommends making revocation one-way (for example a trigger
allowing only `false → true`, with recovery meaning re-enrollment).

The audit hash chain only guards against accidental corruption and helps
trace mistakes; it is not strong evidence against someone who already has
database write access. What defends against that is the signed domain claim.

## What the control plane deliberately does not do (v1)

Worth repeating here since it shapes the whole API surface: the control plane
in v1 does not read a device's `config.xml`, does not modify firewall rules,
and does not restart services on the device. Its job is console sign-in and
user management, enrollment, domain-claim issuance and verification, and
brokering the `frps`/`frpc` tunnel so a user can reach the device's own Web
UI over HTTPS via SNI passthrough — the device's own PHP frontend is served
byte-for-byte untouched. A multi-user console widens who may sign in to the
console; it does not widen what the control plane may do to a device. Anything
beyond that (config backup, config push, bulk upgrade, telemetry) is out of
scope for v1; see the top-level [project README](../README.md) and the roadmap
in [`docs/DESIGN.md`](../docs/DESIGN.md) §11.

## Shared authentication code

Use authcore packages directly for matching capabilities; do not copy or locally
reimplement them. Reusable gaps can be added to authcore with its own regression
tests and PR. NetHub owns user, tenant, invitation, session, and device policy.
[SAML callback routes and persistent replay storage](../deploy/saml-login.md)
are implemented. Their signed-XML and PostgreSQL tests do not replace the pending
independent deployed IdP and combined W6 acceptance.

Run `GOWORK=off go test ./...`, `go vet ./...`, and `go mod verify` in this directory.

Database development and genuine PostgreSQL boundary tests are documented in
[the store README](internal/store/README.md). Web, migrate, init, scoped doctor,
and first-admin commands are implemented. Authz/device flows have scoped hosted
and native validation records; full doctor coverage and the remaining W5-W7
acceptance are still open.
