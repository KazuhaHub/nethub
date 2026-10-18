# deploy/ — self-hosting NetHub

This directory will hold everything needed to self-host the NetHub control
plane: a `docker compose` stack, the Caddy configuration, the per-service
secrets layout, and the operator-facing behaviour of the `nethub init` setup
wizard and the `nethub doctor` preflight checker. Both are **subcommands of the
single `nethub` binary** built from `server/` (see
[`server/README.md`](../server/README.md)); they are not separate tools.

> **Status: not implemented yet.** Nothing described below as `nethub init`,
> `nethub doctor` or the compose stack exists as runnable code. This README
> documents the intended design (v0.3, a draft — see
> [`docs/DESIGN.md`](../docs/DESIGN.md) §7) so it can be built against and
> reviewed before and while it is implemented; it is not a description of a
> working release. See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the
> project's overall pre-alpha status.

## Prerequisites

Before self-hosting NetHub, you need, ahead of time:

1. **A domain you control**, e.g. `router.example.com`.
2. **A wildcard DNS record** for that domain: `*.router.example.com` →
   the public IP of the machine that will run the NetHub relay server
   (e.g. `203.0.113.10`). This is required because each enrolled device gets
   its own subdomain (e.g. `some-device.router.example.com`), and `frps`
   relies on `subDomainHost` + SNI passthrough to route incoming HTTPS
   connections to the right device without the control plane terminating or
   inspecting the TLS session.
3. **Three ports reachable from the public internet** on that server:
   - **443** — Caddy: the console and the device enroll API
     (`/api/v1/devices/*` goes to `nethub authz`, everything else to
     `nethub web`).
   - **7000** — `frps` `bindPort`: the device control channel (TLS), which
     enrolled devices connect to.
   - **8443** — `frps` `vhostHTTPSPort`: browser → device traffic, carrying
     the SNI-passthrough connections.

   Everything else stays on the internal docker network and is never
   published: the `frps` admin API, the `nethub authz` `httpPlugins` endpoint,
   and Postgres.
4. From v1.1 onward only: a DNS provider API token, for DNS-01 per-device
   certificates.

If any of the above isn't true yet, `nethub doctor` (see below) is meant to
catch it before you get further into setup — but you still need to arrange
the domain, DNS, and firewall/router-level port exposure yourself; NetHub
doesn't manage those for you.

## The compose stack

Single host, `docker compose`, no Kubernetes. Planned services:

| Service | What it is |
|---|---|
| `frps` | The frp relay (version-locked to the device-side `frpc`; pinned at 0.71.1 under D4). Public `bindPort` 7000 and `vhostHTTPSPort` 8443, with `subDomainHost` set to your domain; its admin API (`[webServer]`) listens on the internal network only, for `nethub-authz` to poll. Its `httpPlugins` point at an internal `nethub-authz` endpoint, with ops `Login` and `NewProxy`; `NewUserConn` depends on DESIGN Q7 (Weekend 0 only collects data), and `Ping` is a candidate for the cut-off mechanism (see the `nethub-authz` row). |
| `nethub-web` | `nethub web`: the public console (SPA plus `/api/v1/console/...` JSON API). Postgres role `nethub_web`. Never holds the claim signing key or the `frps` admin credentials (nor, per decision #21, the `frps` auth token). |
| `nethub-authz` | `nethub authz`: the device API, the `frps` `httpPlugins` handler, and a poller of the `frps` admin API. The poller only detects anomalies: in the frp 0.71.0 source the admin API has no endpoint that disconnects an online client, so how a revoked or stolen device is actually cut off is unresolved. [`docs/DESIGN.md`](../docs/DESIGN.md) §5 lists the candidate mechanisms, all pending Weekend 0 measurement, and no cut-off latency is promised until then. Holds the claim signing key, the `frps` admin credentials, and the `frps` auth token it hands to devices. Postgres role `nethub_authz`. |
| `caddy` | Public 443 with automatic Let's Encrypt certificates; routes `/api/v1/devices/*` to `nethub-authz` and the rest to `nethub-web`. |
| `postgres` | Postgres 16, not exposed. Four roles: `nethub_owner` (migrations only), `nethub_web`, `nethub_authz` and `nethub_backup` (read-only, for the `backup` service only). The image's own bootstrap superuser (`POSTGRES_PASSWORD`) is used only for the first initialisation; no runtime service uses it. |
| `backup` | A daily `pg_dump`, with optional `rclone` to object storage that you configure yourself. Connects as the read-only role `nethub_backup` (see the note under the secrets table below). |

`nethub migrate` applies the migrations as `nethub_owner` as a one-shot task;
no runtime process uses that role.

A single control-plane VM is a single point of failure: if the relay is down,
remote access to every device is down. v1 accepts that, with no hot standby;
it is your operational choice as the person self-hosting.

`nethub-authz` is a single point of failure too: if it is down, devices cannot
connect or reconnect. If the `Ping` cut-off mechanism is adopted, an authz
outage also drops every tunnel that is already live. In that case authz must
exit when its self-check fails, because Docker's restart policy acts on exited
containers, not on ones marked unhealthy. See DESIGN §5 and §12; this is
pending Weekend 0.

## `nethub init`

`nethub init` is the intended first-run setup wizard. Planned flow:

1. **Ask for your domain** — the base domain you've pointed a wildcard record
   at (e.g. `router.example.com`).
2. **Generate all secrets** — locally, never fetched from anywhere, and never
   a built-in default. The set is:
   - the domain-claim signing key;
   - the `frps` auth token (handed to devices in the enroll response);
   - the `frps` admin user and password;
   - the passwords of the four Postgres roles (`nethub_owner`, `nethub_web`,
     `nethub_authz`, `nethub_backup`);
   - the password of the Postgres bootstrap superuser (the official image's
     `POSTGRES_PASSWORD`);
   - `NETHUB_SECRETS_KEY`, used to encrypt OIDC client secrets at rest;
   - a session key, if one turns out to be needed.
3. **Write per-service secret files** — one location per service (for
   example `deploy/secrets/web/` and `deploy/secrets/authz/`), and each
   container mounts only the files it needs. There is deliberately **no single
   shared `.env` holding everything**: that would undo the separation between
   `nethub web` and `nethub authz`. The same step writes a local
   `docker-compose.override.yml` with your deployment-specific settings.
   `deploy/secrets/`, `docker-compose.override.yml`, `.env`, `*.key` and
   `*.pem` are all `.gitignore`d at the repo root — see the top-level
   `.gitignore` — and must never be committed.

   | Secret | Held by |
   |---|---|
   | Claim signing key | `nethub authz` only |
   | `frps` auth token | `frps` and `nethub authz` (authz hands it to devices in the enroll response) |
   | `frps` admin user/password | `frps` and `nethub authz` |
   | `nethub_owner` password | `nethub migrate` only |
   | `nethub_web` password | `nethub web` only |
   | `nethub_authz` password | `nethub authz` only |
   | `nethub_backup` password | the `backup` service only, in its own secret directory |
   | Postgres bootstrap superuser password (`POSTGRES_PASSWORD`) | the `postgres` container, for its first initialisation only; no runtime service uses it |
   | `NETHUB_SECRETS_KEY` | `nethub web` only |
   | Session key (if needed) | `nethub web` only |

   A secret held by two services (the `frps` auth token and the `frps` admin
   credentials) is mounted into exactly those two and no others. This follows
   DESIGN decision #21.

   **Backup and bootstrap credentials.** Both are proposed in DESIGN (§6 and
   decision #21). They are recommendations, not yet confirmed, and are
   finalized with the migrations:

   - The `backup` service runs `pg_dump` as its own role, `nethub_backup`:
     `LOGIN` and `BYPASSRLS`, read-only (for example by granting it the
     predefined role `pg_read_all_data`, which does not bypass row-level
     security by itself, so `BYPASSRLS` is granted separately), with no write
     privilege of any kind. Its password goes only into the `backup`
     service's own secret directory. A plain role cannot be used for this:
     every tenant-scoped table has `FORCE ROW LEVEL SECURITY`, and `pg_dump`
     turns `row_security` off by default, so a connecting role that is neither
     a superuser nor `BYPASSRLS` makes `pg_dump` fail with an error rather
     than write an incomplete dump.
   - The `postgres` container's bootstrap superuser password is created by
     `nethub init` like the others. It is the official image's
     `POSTGRES_PASSWORD`, used for the container's first initialisation only;
     no runtime service uses it.

   This is the design, not something that has been run: DESIGN §15 records that
   `pg_dump` against this role setup has not been tried yet, and the exact
   grants are fixed when the migrations are written.

4. **Force a backup prompt** — nobody can recover these for you, including the
   project, which holds no global secret of yours. The claim signing key and
   the database credentials are the only copy, so `nethub init` is expected to
   explicitly stop and make you acknowledge you've backed up **every** secret
   in the table above (the `nethub_backup` password and the bootstrap
   superuser password included) somewhere safe before continuing. This secrets
   backup is a separate thing from the daily database dump the `backup`
   service produces. Losing the signing key means every already-enrolled
   device's domain claim can no longer be verified; losing `NETHUB_SECRETS_KEY`
   means the OIDC client secrets stored in the database can no longer be
   decrypted.
5. **Create the first admin user** — with a local password (argon2id). This is
   the break-glass account and local password login stays available even
   after you add OIDC providers; it does not depend on any identity provider.
6. **Run the pre-start preflight checks.** At the end of `init`, it runs the
   `nethub doctor` checks that make sense before the stack is up: wildcard
   DNS, external port reachability, and secrets backup coverage. Role grants
   are checked once migrations have run. Setup fails fast with an actionable
   message.

   Some checks need the running stack: certificate status, the `frps` ↔
   `nethub authz` loopback, and the last `pg_dump`. Run `nethub doctor` again
   after `docker compose up -d` to cover them.

### After init: OIDC providers

`init` does not configure single sign-on. After `docker compose up -d`, sign in
as the first admin and add OIDC providers in the console (optional; with none
configured, everyone signs in with a local password). Multiple providers are
supported. Users join by invitation only — there is no self sign-up in v1 — and
an external identity is bound by `(issuer, subject)`, never by email alone.
An invitee who wants to use an identity provider has to start from the invite
link: the invite is bound into that sign-in flow, and the binding completes
only if the invite token is still valid and unused, the ID token has
`email_verified=true`, and its email matches the invite. A sign-in through an
identity provider without the link is rejected, even if its email matches a
pending invite. SAML is included in v1 through authcore/saml.

Console sign-in and SSO do **not** protect the device's own OPNsense GUI: that
page keeps its own login, and `https://<subdomain>.router.example.com:8443`
reaches it for anyone who knows or guesses the hostname. A possible source-IP
gate is an open question (DESIGN Q7); either way, enabling OPNsense's own TOTP
two-factor authentication on each device is recommended.

## `nethub doctor`

`nethub doctor` is the intended standalone preflight/health checker — runnable
both during `nethub init` and later, independently, when something's not
working. Planned checks:

- **Wildcard DNS resolution** — that `*.router.example.com` (your configured
  domain) actually resolves, and resolves to the expected server IP, not
  just that the base domain resolves.
- **External port connectivity** — that **443, 7000 and 8443** are actually
  reachable from outside your network, checked with an external echo service
  rather than by looking at local sockets (catches the common case of a
  firewall silently swallowing a port, or CGNAT on the *server* side).
- **Certificate status** — that Caddy has successfully obtained/renewed a
  valid TLS certificate for the configured domain(s) on 443, and how many days
  remain, and that nothing is serving a self-signed or expired cert where a
  real one is expected.
- **`frps` ↔ `nethub authz` loopback** — that `frps`'s `httpPlugins` callbacks
  (`Login` / `NewProxy`) can actually reach `nethub authz` over the internal
  path used for the dual signature+DB check, so a broken internal wiring
  doesn't only surface later as an opaque device-enroll failure.
- **`web` ↔ `authz` separation** — a sanity check that the split really holds:
  the `nethub-web` container has no claim signing key file, no `frps` admin
  credentials and no `frps` auth token (decision #21 gives the token to `frps`
  and `nethub authz` only), and the `nethub_web` Postgres role has no write
  privilege on `devices`' identity columns (checked from privilege metadata
  such as `information_schema.column_privileges`, without performing a real
  write).
- **Secrets backup** — that the secrets backup `nethub init` asked for is
  actually present, and that it covers every secret in the table above,
  including the `nethub_backup` password and the Postgres bootstrap superuser
  password (the loss scenario DESIGN §13 lists as #12). How `doctor` verifies
  this is not specified yet.
- **Last `pg_dump` succeeded** — that the most recent dump by the `backup`
  service completed. A connecting role without `BYPASSRLS` makes `pg_dump`
  fail outright on the `FORCE`d tables (see the note under the secrets table).
- **`frp` version match** — that the vendored `frpc` version shipped in the
  OPNsense plugin and the `frps` version run by the control plane are the
  expected matching pair (frp 0.71.1 under D4), since a
  version mismatch between `frpc` and `frps` is a plausible source of subtle
  tunnel failures.

Each check is intended to fail with a specific, actionable message (which
prerequisite is missing/misconfigured) rather than a generic "setup failed."

## Directory contents (planned)

Planned; exact file names are finalized when code lands.

- `docker-compose.yml` — the single-machine stack described above: `frps`,
  `nethub-web`, `nethub-authz`, `caddy`, `postgres`, `backup`.
- the Caddy configuration, including the `/api/v1/devices/*` routing split.
- `secrets/` — the per-service secret directories (`secrets/web/`,
  `secrets/authz/`, …, and one for each other service that holds a secret,
  such as `backup`, whose directory holds only the `nethub_backup` password)
  where generated secrets land at runtime; **never committed** (see the
  top-level `.gitignore`).

The `nethub` CLI itself is not in this directory: `init`, `doctor` and
`migrate` are subcommands of the server binary, whose code is planned under
`server/cmd/nethub/` (see [`server/README.md`](../server/README.md)).

None of the above exists as runnable code yet; this README is the design to
build against.
