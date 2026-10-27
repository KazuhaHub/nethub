# NetHub console API

Updated 2026-10-26 against the Web router, DTOs and store operations. This
reference distinguishes implemented routes from reserved proposals. Local
sessions, device inventory/enrollment, Open/Revoke/disconnect, users, invitations
and OIDC/SAML provider management and login are implemented. Actual two-Dex and
signed Keycloak deployment evidence is separate from public-provider and combined
W5-W7 acceptance, which remain open.

Update this document with API contract changes. See [deployment](deployment.md),
[protocol](protocol.md) and [threat model](threat-model.md) for runtime boundaries
and measured limits. Historical design proposals do not establish HTTP routes.

## Contents

- [1. Scope](#1-scope)
- [2. Conventions](#2-conventions)
- [3. Endpoint summary](#3-endpoint-summary)
- [4. Session and sign-in](#4-session-and-sign-in)
- [5. Devices and enroll tokens](#5-devices-and-enroll-tokens)
- [6. Users and invites](#6-users-and-invites)
- [7. OIDC providers](#7-oidc-providers)
- [SAML providers](#saml-providers)
- [8. Audit log and traffic](#8-audit-log-and-traffic)
- [9. Error codes](#9-error-codes)
- [10. Decisions and remaining work](#10-decisions-and-remaining-work)

## 1. Scope

Covered: everything under `/api/v1/console/`, served by `nethub web` and
called by the console in the browser, plus OIDC/SAML browser callbacks, public
SP metadata and the private health check.

Not covered:

- the **device API** (`/api/v1/devices/*`: enroll, rotate, unenroll, status),
  served by `nethub authz` and defined in [`proto/`](../proto/README.md).
  Protocol schemas alone do not establish an implemented device route;
- the **`frps` plugin endpoint** (internal network only, served by
  `nethub authz`);
- the **`nethub` CLI** (`init`, `migrate`, `doctor`, …), see
  [`deploy/README.md`](../deploy/README.md).

## 2. Conventions

### Base URL and format

- Base URL: `https://<console host>/api/v1/console`. D18 uses a deployment-configured
  console hostname separate from the device wildcard. Requests with a different
  Host are rejected; forwarded host headers never select the console origin.
- Requests and responses are JSON (`Content-Type: application/json`, UTF-8).
  Ordinary JSON request bodies larger than 64 KiB are rejected with `413`.
  Administrator SAML writes and the SAML browser callback have separate bounds
  described below; metadata responses are XML and callbacks redirect the browser.
- Timestamps are RFC 3339 strings in UTC, for example `"2026-10-16T08:00:00Z"`.
- IDs are UUID strings.
- Unknown fields in a request body are rejected (`400 invalid_request`) rather
  than ignored.
- Bodies must be UTF-8 JSON objects. Repeated top-level keys, trailing JSON values,
  compressed bodies, and non-UTF-8 content are rejected. GET/HEAD do not accept bodies.

### Authentication

- The console uses a **server-side session**. After sign-in the server sets a
  cookie named `__Host-nethub_session`, with `HttpOnly`, `Secure`,
  `SameSite=Lax`, `Path=/` and no `Domain` attribute.
- The `__Host-` prefix matters here. Device pages are served on sibling
  subdomains (`<subdomain>.router.example.com`) whose content is controlled by
  whoever owns the device, and the prefix stops them from setting or
  overriding the console's cookies.
- The five-minute `__Host-nethub_oidc` flow cookie uses `SameSite=Lax`.
  Only the five-minute `__Host-nethub_saml` browser-binding cookie uses
  `SameSite=None`, because the IdP returns a cross-site form POST. Both are
  HttpOnly/Secure/Path=/ with no Domain; the ordinary session remains Lax.
- The cookie holds an opaque random token. The database stores only its hash.
- Sessions have an idle timeout and an absolute timeout, and can be revoked
  (DESIGN §6). Initial defaults are 30 minutes idle and 12 hours absolute.
  Current active-account and role state is reloaded from PostgreSQL on each request.
- Protected endpoints without a valid session get `401 unauthenticated`.
  `GET /session` instead returns `200 { "signed_in": false }`. Public catalogs,
  metadata and browser-admission endpoints have their own rules below.

### CSRF

- **Ordinary API requests with a body** use `Content-Type: application/json`;
  otherwise they get `415 unsupported_media_type`. The SAML ACS is the explicit
  cross-site form exception, validated through the browser-bound signed flow.
- **Endpoints called before sign-in** must carry an `Origin` header equal to
  the console's own origin. A missing or foreign `Origin` gets
  `403 csrf_failed`. These endpoints are `POST /login`, `POST /invites/inspect`,
  `POST /invites/accept`, `POST /oidc/{slug}/start` and
  `POST /saml/{slug}/start`. SAML callback POSTs use signature, request, destination,
  replay and browser-binding checks rather than the console Origin or session CSRF.
- **Every other request** whose method is not `GET` or `HEAD` must carry the
  header `X-CSRF-Token: <token>`. The token is per session and is returned by
  `POST /login` and `GET /session`. A missing or wrong token gets
  `403 csrf_failed`. A present but foreign `Origin` is rejected too.
- **`GET` requests never change business state**, with one exception:
  `GET /oidc/{slug}/callback`. That endpoint is protected by `state` plus the
  flow cookie. Authenticated reads update session activity bookkeeping; they
  never renew a device source-IP grant or extend absolute session expiry.

### Roles

There is one tenant per instance in v1 (DESIGN §6). The tenant is implicit and
never appears in the API.

| Role     | Can                                                                                             |
| -------- | ----------------------------------------------------------------------------------------------- |
| `admin`  | Implemented device operations across the instance; user, invitation and provider administration |
| `member` | Their own devices and enroll tokens; local session and logout                                   |

A member asking for someone else's device gets `404 not_found`, not `403`, so
the API does not reveal that the device exists.

### Errors

Every error response has this shape:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "Invalid provider configuration"
  }
}
```

- `code` is stable and meant for the console to branch on; the list is in
  [§9](#9-error-codes).
- `message` is for humans and may change.
- Authentication failures always use a generic message. They do not say
  whether the email exists, whether the password was wrong, or whether the
  account is disabled.

### Pagination

List endpoints accept `?limit=` (default 50, maximum 200) and `?cursor=`, and
return:

```json
{ "items": [ ... ], "next_cursor": "opaque-string-or-null" }
```

### Response headers

All responses carry:

- a strict `Content-Security-Policy` (at least `default-src 'self'`,
  `frame-ancestors 'none'`, `base-uri 'none'`);
- `Cross-Origin-Opener-Policy: same-origin`, so a device tab opened from the
  console cannot reach back into it;
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: no-referrer`.

API responses also carry `Cache-Control: no-store`.

**HSTS.** The Web response sets `max-age=31536000` without `includeSubDomains`.
Console and device subdomains have separate endpoints and trust; device content
is not the console. v1 implements [GUI certificate management](protocol.md);
a successful API response is not an independent check of the served device leaf.

### Secrets never come back

- Enroll tokens and invite links are shown **once**, in the response that
  creates them.
- OIDC client secrets and imported SAML metadata are write-only. SAML SP private
  keys never appear in responses; public SP metadata includes its certificate.
- No response ever contains a password hash, session token, device secret,
  domain claim or any `*_hash` column.

### Rate limits

These endpoints are rate limited per client IP and, where there is one, per
account or action key:

- `POST /login`
- `POST /invites/inspect`
- `POST /invites/accept`
- OIDC/SAML starts and callbacks
- device Open/Revoke/disconnect
- `POST /enroll-tokens`

A limited request gets `429 rate_limited` with a `Retry-After` header.

Per-account limiting slows attempts down. It never locks the account:
otherwise anyone who knows the break-glass admin's email could lock that
admin out.

The client IP is taken from `X-Forwarded-For` only when the request comes from
the declared trusted proxy (Caddy); DESIGN §6.

Login and enroll issuance have separate process-local windows: ten attempts
per source IP and five per normalized account/user per minute. Each counter map
holds at most 10,000 live keys; new keys fail closed at capacity until expiry.
Password work also has a two-verification concurrency bound, with Retry-After: 1
when busy. These limits are for the single-process deployment, not replica-wide.
OIDC and SAML share start/callback limiter instances, using the source IP and
provider slug as the second key. Callback refusal redirects to the generic SSO
error page; it does not expose protocol or upstream diagnostics.

### Audit

Endpoints marked **audited** write an entry to `audit_log`. The entry records
the acting user, the client IP and the target. It never records secrets.

W3 successful login, logout, and token issuance commit atomically with their audit
entry. Invalid-credential attempts admitted by the login budget use an anonymous
system actor and record source IP, without attempted email/password. Early malformed,
CSRF, or rate-limit rejection does not append an audit row. Raw credentials,
cookie/CSRF values, and enrollment tokens are absent from application/audit logs.

## 3. Endpoint summary

"Phase" refers to the MVP weekends in DESIGN §10 (W3 to W7).

| Method and path                                | Who                              | Phase | Audited                        |
| ---------------------------------------------- | -------------------------------- | ----- | ------------------------------ |
| `GET /healthz` (outside the API prefix)        | anyone                           | W3    | no                             |
| `POST /login`                                  | anyone                           | W3    | yes                            |
| `POST /logout`                                 | signed in                        | W3    | yes                            |
| `GET /session`                                 | anyone                           | W3    | no                             |
| `GET /oidc/providers`                          | anyone                           | W6    | no                             |
| `POST /oidc/{slug}/start`                      | anyone                           | W6    | failed admission when budgeted |
| `GET /oidc/{slug}/callback` (browser redirect) | anyone                           | W6    | yes                            |
| `GET /saml/providers`                          | anyone                           | W6    | no                             |
| `GET /saml/{slug}/metadata`                    | anyone; available provider       | W6    | no                             |
| `POST /saml/{slug}/start`                      | anyone                           | W6    | failed admission when budgeted |
| `POST /saml/{slug}/callback` (IdP form POST)   | browser-bound flow               | W6    | yes                            |
| `GET /devices`                                 | admin: all; member: own          | W3    | no                             |
| `POST /devices/{id}/open`                      | admin, or owner                  | W5    | yes                            |
| `POST /devices/{id}/revoke`                    | admin, or owner                  | W5    | yes                            |
| `POST /devices/{id}/disconnect`                | admin, or owner; already revoked | W5    | yes                            |
| `POST /enroll-tokens`                          | signed in                        | W3    | yes                            |
| `GET /users`                                   | admin                            | W6    | no                             |
| `PATCH /users/{id}`                            | admin                            | W6    | yes                            |
| `POST /invites`                                | admin                            | W6    | yes                            |
| `GET /invites`                                 | admin                            | W6    | no                             |
| `DELETE /invites/{id}`                         | admin                            | W6    | yes                            |
| `POST /invites/inspect`                        | anyone holding an invite token   | W6    | no                             |
| `POST /invites/accept`                         | anyone holding an invite token   | W6    | yes                            |
| `GET /oidc-providers`                          | admin                            | W6    | no                             |
| `POST /oidc-providers`                         | admin                            | W6    | yes                            |
| `PATCH /oidc-providers/{id}`                   | admin                            | W6    | yes                            |
| `DELETE /oidc-providers/{id}`                  | admin                            | W6    | yes                            |
| `GET /saml-providers`                          | admin                            | W6    | no                             |
| `POST /saml-providers`                         | admin                            | W6    | yes                            |
| `PATCH /saml-providers/{id}`                   | admin                            | W6    | yes                            |
| `DELETE /saml-providers/{id}`                  | admin                            | W6    | yes                            |

The table lists implemented routes. Phase identifies their plan stage, not full
stage acceptance. These paths are reserved and have no handler: `POST /me/password`,
`GET /devices/{id}`, `PATCH /devices/{id}`, `GET /audit` and `GET /traffic`.
Their proposed behavior below is not an available API contract.

All paths below are relative to `/api/v1/console` unless stated otherwise.

## 4. Session and sign-in

### `GET /healthz`

Served by `nethub web` on the internal network for the container health
check. The generated Caddy answers `404` for `/healthz` and `/healthz/*`.
An external reverse proxy must preserve that isolation.

Returns `200` with the body `ok` when the process can reach the database. It
returns no version or configuration details.

### `POST /login`

Signs in with a local password.

Request:

```json
{ "email": "admin@example.com", "password": "correct horse battery staple" }
```

Response `200`, with the session cookie set:

```json
{
  "user": { "id": "1f6c…", "email": "admin@example.com", "role": "admin" },
  "csrf_token": "…",
  "session_expires_at": "2026-10-16T20:00:00Z"
}
```

Errors:

- `401 invalid_credentials`, for a wrong email, a wrong password, a disabled
  user, or a user without a local password. These cases are deliberately
  indistinguishable.
- `429 rate_limited`.

`POST /login` needs no CSRF token, because there is no session yet. It does
need a matching `Origin` header ([§2](#csrf)), which prevents another site
from signing the browser into an attacker's account.

### `POST /logout`

Deletes the server-side session and clears the cookie. Response `204`.
Request: `{}` with JSON Content-Type and the session CSRF header.

### `GET /session`

Response `200` when signed in:

```json
{
  "signed_in": true,
  "user": { "id": "1f6c…", "email": "admin@example.com", "role": "admin" },
  "csrf_token": "…",
  "session_expires_at": "2026-10-16T20:00:00Z"
}
```

Response `200` when not signed in: `{ "signed_in": false }`.

### `POST /me/password`

**Reserved:** no handler exists. Self-service password change and its proposed
request/error contract are not available. Local-password acceptance through an
invitation is implemented separately below.

### OIDC sign-in

The backend and console pages are implemented. Actual [two-Dex deployment](../deploy/validation-two-dex.md)
passed; public-provider integration and combined W6 acceptance remain open.
See [browser state and admission scope](../deploy/oidc-login.md).

The flow follows DESIGN §6 and decision #22: authorization code with PKCE,
`state` and `nonce` kept server-side, identities bound by `(issuer, subject)`.

**`GET /oidc/providers`** lists the enabled providers for the sign-in page:

```json
{ "items": [{ "slug": "company-sso", "display_name": "Company SSO" }] }
```

**`POST /oidc/{slug}/start`** begins a flow.

- Request: `{}` for an ordinary sign-in, or `{ "invite_token": "…" }` when the
  user arrived from an invite link (see [§6](#6-users-and-invites)).
- The server creates the flow record, which holds `state`, `nonce`, the PKCE
  verifier and, if present, the invite. It sets a short-lived flow cookie.
  State/browser bearers and the invitation are stored as digests; nonce/verifier
  and configuration binding use a separate authenticated encrypted envelope.
  The database lifetime is five minutes. An explicitly provided invite token
  must be canonical; empty/null values do not fall back to ordinary sign-in.
- Response `200`: `{ "redirect_url": "https://idp.example.com/authorize?…" }`.
  The console then navigates the browser to that URL.
- An existing active session returns `409 already_signed_in`; switching accounts
  requires explicit logout. Failed/disabled/unavailable providers use a generic
  `401 sso_failed`, or `503 sso_unavailable` if no backend is configured. Starts
  are rate limited. The provider catalogs reject query parameters.

This is a `POST` so the invite token travels in the body. It never appears in
a URL that could end up in access logs or browser history.

**`GET /oidc/{slug}/callback`** is the redirect URI registered at the
provider. It is a browser endpoint, not a JSON one.

- The server checks `state` against the flow cookie and exchanges the code
  using the PKCE verifier.
  Matching state is atomically consumed before remote I/O, and its encrypted
  payload is cleared. Replay and failed-exchange retry require a new flow.
  HEAD does not invoke the callback. Duplicate parameters/cookies are refused.
- It verifies the ID token (issuer, audience, expiry) and checks `nonce`.
- Then it decides:
  - if `(issuer, subject)` is bound to an active user, it signs that user in;
  - otherwise, only if the flow was started with an invite token, and the
    invite is valid, unused and unexpired, and `email_verified` is `true`,
    and the email matches the invite, it creates the user, binds the
    identity, marks the invite used and signs in;
  - in every other case it refuses.
- Bound identities are looked up by the verified token's `(iss, sub)`, never
  by the provider record. The `{slug}` in the callback must match the
  provider recorded in the flow.
- On success it redirects to the console home page.
- On any failure it redirects to `/login?error=sso_failed`. The reason is
  recorded in the audit log, not shown to the browser.
  Reasons are fixed categories; raw upstream diagnostics are never retained.

## 5. Devices and enroll tokens

### The device object

```json
{
  "id": "8d0e…",
  "label": "Branch office",
  "hostname": "fw-branch",
  "subdomain": "abcd1234",
  "url": "https://abcd1234.router.example.com:8443",
  "platform": "opnsense",
  "platform_version": "26.7.7",
  "agent_version": "0.1.0",
  "capabilities": ["remote.web"],
  "cluster_hint": null,
  "online": true,
  "last_seen_at": "2026-10-16T08:00:00Z",
  "enrolled_at": "2026-10-01T12:00:00Z",
  "revoked": false,
  "revoked_at": null,
  "owner": { "id": "1f6c…", "email": "admin@example.com" },
  "service_state": null,
  "last_report_at": null,
  "last_reconcile_success": null,
  "last_reconcile_at": null,
  "gui_certificate": {
    "state": "unsupported",
    "assigned_host": null,
    "valid_until": null,
    "confirmed_at": null
  },
  "disconnect": null
}
```

- `online` means authz reported the tunnel within the last 45 seconds, derived
  from non-future `last_seen_at`. This is a recent observation subject to polling
  delay, not a real-time GUI health check. `nethub web` never queries `frps`.
  Authz observation wiring is implemented; native timing evidence and remaining
  combined W5 acceptance are recorded separately in the deployment reports.
- `cluster_hint` is a nullable display string, matching the database model.
- Service/reconcile fields are authenticated device reports. `gui_certificate`
  summarizes accepted installation/renewal state, not a probe of relayed TLS.
  `disconnect` is null or the narrow receipt described below. Device keys,
  certificate requests/chains and raw reports are absent.
- `owner` is included for admins. For members it is always themselves.
- The exact column list is settled with the data model (DESIGN §6). Hash and
  claim columns are never exposed.

### `GET /devices`

Lists devices. Admins see all devices; members see only their own.

- Optional filters: `?online=true|false`, `?revoked=true|false`.
- Response: a paginated list of device objects.
- W3 uses UUID-ascending keyset pagination. The opaque base64url cursor identifies
  the last returned UUID; the server re-applies actor/tenant filters on every page.
  Limit is 1-200 (default 50). Unknown, repeated, or malformed query parameters
  return `400 invalid_request`.

An enabled current admin can also receive an optional `relay_alerts` array of up
to 100 latest active incidents, independent of the device-page filter. Members
never receive it; an empty array is omitted. Each item contains canonical `id`,
nullable `device_id`, `kind` (`unknown_proxy`, `domain_mismatch`, `revoked_online`),
`response` (`alarm_only`, `revoked`, `already_revoked`) and `confirmed_at`.
Unknown proxies have no device ID and are always alarm-only. Raw relay names and
digest keys are excluded. These are confirmed observations/decisions, not receipts
that every browser stream closed. See [anomaly policy](../deploy/relay-anomalies.md).

### `GET /devices/{id}`

**Reserved:** no device-detail route exists. Read authorized device projections
through `GET /devices` and its filters/pagination.

### `PATCH /devices/{id}`

**Reserved:** no label-editing HTTP route exists. Device identity/assignment and
credentials cannot be changed through a proposed display-label endpoint.

### `POST /devices/{id}/open`

Request: `{}` without query parameters. Response `200`:

```json
{
  "url": "https://abcd1234.router.example.com:8443",
  "gate_expires_at": "2026-10-24T08:30:00Z"
}
```

The API, transactional database grant and generated relay's NewUserConn checks
are implemented. Existing bundles must include NewUserConn in the frps callback
operation list. The console button and scoped native checks are implemented; combined native
mobile/timing acceptance remains open. An API response alone does not verify a
successful GUI connection.

The console opens it in a new tab with `noopener,noreferrer`, so the device
page cannot reach the console tab. It also shows the hostname, so the user
can check where they are going. A compromised console can still mislead its
operator; the real device origin and its own authentication remain relevant.

- This explicit call registers the server-resolved exact source IP for 30 minutes
  using the database clock, and appends a device/actor/source audit in the same
  transaction. Another explicit call renews the same grant; reads and traffic
  do not. Caller-supplied IPs, actor, destination and expiry are rejected.
- Current database ownership/admin and enabled-account checks precede the grant.
  A non-owner, foreign-tenant or missing device returns `404 not_found` before
  any revocation state is exposed. An authorized revoked device returns
  `409 device_revoked`. Invalid session/CSRF and bounded-attempt errors retain
  the common `401`, `403` and `429` behavior.

### `POST /devices/{id}/revoke`

Marks the device revoked. Request: `{}`. Response `200`:
`{ "revoked": true, "revoked_at": "RFC3339 timestamp" }`.

- Revocation is one-way in the implementation: a revoked device must
  re-enroll (DESIGN §6; enforced in the database).
- D6 denies Ping, Login, and NewProxy together. Live tunnel interruption uses
  the confirmed heartbeat mechanism, subject to the W0 backend-failure/hang limits.
  Concurrent exact retries preserve the first timestamp and audit. No immediate
  all-stream cutoff is promised.

### `POST /devices/{id}/disconnect`

The manual "confirmed stolen, cut now" bypass (DESIGN §5).

- It requires the device to be revoked already.
- `nethub web` only records the request. `nethub authz` carries it out,
  because only authz holds the relay credentials.
- An enabled owner or tenant admin can call it with `{}`. An owned active device
  returns `409 device_not_revoked`; a missing/foreign device returns `404` first.
- Response `200` contains `request_id`, `requested_at`, nullable `armed_at` and
  `state` (`pending` or `armed`). The first request and processing time are immutable.
- Authz arms the request only after its published memory snapshot denies the
  tenant/device; audit and status commit together. `armed` means heartbeat rejection
  is ready, not that all established streams were observed closed. Inventory
  includes the same narrow receipt for authorized devices.

### `POST /enroll-tokens`

Creates a one-time enroll token for a new device, owned by the caller.

Request: `{}`.

Response `201`:

```json
{ "token": "…", "expires_at": "2026-10-16T08:15:00Z" }
```

- The token is shown only in this response. The database stores its hash.
- The expiry comes from the database default (15 minutes) and cannot be set
  by the caller (DESIGN §6).
- W3 emits 32 random bytes encoded as unpadded base64url, and persists only SHA-256
  of those bytes. It accepts no owner/tenant/expiry override. D19 uses a separate
  console HTTPS address input alongside the token; the address is not embedded
  in this API response or selected by token contents.
- The web role has limited SELECT on the returned status columns; it cannot read
  token hashes, change expiry, or consume the token. Authz owns atomic consumption.
- Errors: `429 rate_limited`.

## 6. Users and invites

### The user object

```json
{
  "id": "1f6c…",
  "email": "alice@example.com",
  "role": "member",
  "disabled": false,
  "has_password": true,
  "identities": [
    { "provider_slug": "company-sso", "linked_at": "2026-10-10T09:00:00Z" }
  ],
  "created_at": "2026-10-10T09:00:00Z"
}
```

### `GET /users`

Admin only. A paginated list of user objects.

The implemented backend accepts `limit` (1–200, default 50) and an opaque
`cursor`, returning `{ "items": [...], "next_cursor": null | "..." }`.
Passwords, hashes, identity subjects and provider secrets are never projected.
The user-management interface is available at `/users`. GET `/users`,
GET `/devices`, GET `/oidc-providers`, GET `/saml-providers` and GET `/session`
accept exactly one `X-NetHub-Background: 1` header for passive lookup without
idle-time renewal.
Explicit reads and all mutations use active lookup.

### `PATCH /users/{id}`

Admin only. Request: any of `{ "role": "admin" | "member", "disabled": true | false }`.

- Disabling a user revokes all of their sessions immediately.
- A later re-enable does not restore deleted sessions. Role changes take effect
  on the next authenticated request. Actor authority is checked again inside the
  transaction after acquiring account locks; request-supplied roles are never
  used as authority.
- Account changes, session deletion and the `user.updated` /
  `auth.sessions_revoked` audit records commit atomically. An unchanged request
  returns the current user without appending another change event.
- Errors:
  - `409 last_admin`, when the change would leave no active admin. This
    includes disabling or demoting yourself as the last admin.
  - `409 last_local_admin`, when the change would leave no active admin who
    has a local password. The break-glass account must never depend on an
    identity provider (DESIGN §6, §9).

### Invite flow

1. An admin calls `POST /invites`.
2. The response contains an invite link of the form
   `https://<console host>/invite#<token>`. The token is in the URL fragment,
   which browsers do not send to the server. The admin passes the link to the
   invitee themselves; v1 sends no email.
3. The invitee opens the link. The console reads the token from the
   fragment, removes it from the address bar with `history.replaceState`,
   and calls `POST /invites/inspect`.
4. The invitee either sets a password (`POST /invites/accept`) or chooses a
   provider and starts its `POST /oidc/{slug}/start` or
   `POST /saml/{slug}/start` with the invite token.

### `POST /invites`

Admin only. Request: `{ "email": "alice@example.com", "role": "member" }`.
An optional `provider_id` restricts the invitation to an enabled OIDC or SAML
provider; null
means unrestricted. A restricted invitation cannot use local-password acceptance.

Response `201`:

```json
{
  "id": "…",
  "invite_url": "https://console.example.com/invite#…",
  "expires_at": "2026-10-19T08:00:00Z"
}
```

- The approved lifetime is 72 hours, generated from one database timestamp.
- Errors: `409 user_exists`.

### `GET /invites`

Admin only. Lists pending invites (`id`, `email`, `role`, `created_at`,
`expires_at`, `provider_id`, `created_by`), never the token.
The implemented page accepts `limit` (1–200, default 50) and `cursor`, and returns
`{ "items": [...], "next_cursor": null | "..." }`. `created_by` has `id`/`email`.

### `DELETE /invites/{id}`

Admin only. Withdraws a pending invite. Response `204`.
No request body is accepted. Session CSRF and Origin checks still apply. An exact
withdrawal retry preserves the first timestamp and audit.

### `POST /invites/inspect`

Request: `{ "token": "…" }`.

Response `200`:

```json
{
  "email": "alice@example.com",
  "role": "member",
  "expires_at": "…",
  "password_allowed": true,
  "providers": [
    { "slug": "company-sso", "display_name": "Company SSO", "kind": "oidc" }
  ]
}
```

Errors: `404 invite_invalid`, for an unknown, used, expired or withdrawn
token. These cases are deliberately indistinguishable. Also `429 rate_limited`.

### `POST /invites/accept`

Accepts with a local password. Request: `{ "token": "…", "password": "…" }`.

- Response `200`: same body as `POST /login`, with the session cookie set.
- Errors: `404 invite_invalid`, `422 weak_password`, `429 rate_limited`.

The token consumption, new account, first session and both audit entries commit
atomically. Existing emails and provider-restricted local claims are refused;
no account is attached by email. Validity is checked after invitation/mailbox
lock waits. An uncertain delivery does not permit token replay: the holder can
explicitly sign in with the chosen password. The invitation pages support this
local-password and OIDC/SAML claims. Existing accounts are never linked by
matching email alone. See [invitation scope](../deploy/invitations.md),
[OIDC admission](../deploy/oidc-login.md) and [SAML admission](../deploy/saml-login.md).

## 7. OIDC providers

Admin only. Each provider is shown as an object; `client_secret` never appears
in a response.

```json
{
  "id": "…",
  "slug": "company-sso",
  "display_name": "Company SSO",
  "issuer_url": "https://idp.example.com",
  "client_id": "nethub",
  "has_client_secret": true,
  "scopes": ["openid", "email", "profile"],
  "enabled": true,
  "redirect_uri": "https://console.example.com/api/v1/console/oidc/company-sso/callback",
  "created_at": "…"
}
```

`redirect_uri` is computed by the server. It is shown so the admin can
register it at the provider.

### `GET /oidc-providers`

A paginated list of provider objects.

### `POST /oidc-providers`

Request:
`{ "slug", "display_name", "issuer_url", "client_id", "client_secret", "scopes"?, "enabled"? }`.

- Before saving, the server fetches the issuer's discovery document. If that
  fails, the request is rejected with `422 oidc_discovery_failed`. The error
  does not say why the fetch failed.
- This fetch, and the later fetches of the provider's signing keys, must not
  become a way to probe the internal network. Rules:
  - `issuer_url` must be `https`;
  - private, loopback and link-local addresses are refused, unless the
    deployer explicitly allows a host (for example a Dex instance inside the
    compose stack for testing).
- `client_secret` is encrypted with `NETHUB_SECRETS_KEY` before it is stored
  (DESIGN §6). The key is supplied by the private `--secrets-key-file`, not its
  plaintext environment value. [Envelope/startup foundation](../deploy/provider-secrets.md)
  is implemented. Provider writes and their SQL acceptance tests are implemented;
  [backend scope and validation limits](../deploy/oidc-providers.md) distinguish
  source/SQL evidence from [deployed login acceptance](../deploy/validation-two-dex.md).
  The management and sign-in pages are implemented.
- Response `201`: the provider object.
- Errors: `409 slug_taken`, `422 oidc_discovery_failed`.

### `PATCH /oidc-providers/{id}`

Any field of the create request except `slug`. Sending `client_secret`
replaces it; omitting it keeps the stored one. Response: the provider object.
JSON null is invalid. An explicit empty secret removes it only if discovery
accepts a public client. Display-name edits and disabling work while the IdP is
offline; protocol edits and enabling require discovery. An edit that loses a
concurrent revision race returns `409 provider_changed`; reload before editing.

`issuer_url` cannot be changed once any user is bound to the provider
(`409 provider_in_use`): bindings are by issuer.

### `DELETE /oidc-providers/{id}`

Response `204`.

- If users are still bound to the provider, deletion is refused with
  `409 provider_in_use`. Disable it instead (`"enabled": false`).
- Deleting an unbound provider withdraws its unused restricted invitations and
  clears its credential atomically. A disabled tombstone preserves provider and
  invitation history; its immutable slug remains reserved. It is excluded from
  listing and editing. Repeated deletion returns 404. See [lifecycle](../deploy/oidc-providers.md).

## SAML providers

### Administration

`GET /saml-providers` returns a paginated administrator-only list using the same
`limit`/`cursor` rules as OIDC. `POST /saml-providers` creates a provider and
returns `201`; `PATCH /saml-providers/{id}` returns the updated projection;
`DELETE /saml-providers/{id}` returns `204`. Mutations require the live admin
session and normal session CSRF checks. A provider projection is:

```json
{
  "id": "…",
  "slug": "company-saml",
  "display_name": "Company SAML",
  "entity_id": "https://idp.example.com/saml",
  "email_attribute": "mail",
  "enabled": false,
  "has_signing_key": true,
  "created_at": "…",
  "metadata_uri": "https://console.example.com/api/v1/console/saml/company-saml/metadata",
  "acs_uri": "https://console.example.com/api/v1/console/saml/company-saml/callback"
}
```

Creation requires `slug`, `display_name`, `entity_id`, `metadata_xml` and
`email_attribute`; `enabled` defaults to false. Slugs are immutable/reserved
lowercase DNS-style labels, shared across provider protocols. PATCH accepts the
mutable fields only; omitted metadata retains the saved XML and SP signing key.
Null, repeated, empty-patch, unknown or mistyped fields are refused. Supply only
changed fields; a `409 provider_changed` means reload before another attempt.

`entity_id` selects the IdP in the supplied XML. Obtain metadata through a trusted
administrator channel: parsing and endpoint policy do not authenticate its source.
NetHub does not fetch an arbitrary metadata URL. Decoded metadata is bounded to
one MiB of UTF-8 XML; only these admin writes accept up to six MiB plus 64 KiB of
JSON wire data to allow escaping, after administrator/CSRF checks. Metadata,
expiry and HTTPS/DNS endpoint policy failures return `422 saml_metadata_invalid`.
Renaming/disabling works offline; enabling and protocol changes validate again.
A bound IdP entity cannot change (`409 provider_in_use`).

Each provider has an independent encrypted SP signing identity. `metadata_xml`
and private SP key material are never returned. The computed `metadata_uri`
is also the SP entity ID; `acs_uri` is its exact POST reply address. Register
these with the IdP before enabling sign-in. Metadata edits do not silently rotate
the registered SP key. Explicit signing-key/certificate rotation remains open.

Deletion refuses bound identities. Otherwise it withdraws unused restricted
invitations, clears encrypted private material and tombstones the disabled
provider atomically with audit. The slug stays reserved; deleted records no
longer appear in lists or public metadata. Another deletion returns `404`.
See [provider boundaries](../deploy/saml-providers.md).

### Browser admission and metadata

`GET /saml/providers` lists enabled choices without authentication or query
parameters. SAML catalog items include `"protocol": "saml"`, `slug` and
`display_name`. The OIDC catalog omits the optional protocol field. Invitation
inspection instead uses `kind` for either provider protocol.

`GET /saml/{slug}/metadata` returns public SP XML with
`Content-Type: application/samlmetadata+xml; charset=utf-8`. It accepts HEAD,
requires no session and remains available while disabled for initial registration.
It publishes a certificate, persistent NameID format and signed AuthnRequest
policy, never a private key or a login receipt. Query parameters are refused.

`POST /saml/{slug}/start` uses the same Origin, JSON `{}` or optional
`invite_token`, existing-session and rate-limit rules as OIDC start. It returns
`200 { "redirect_url": "https://idp.example.com/…" }` and the dedicated
five-minute SAML browser-binding cookie. The console navigates to the signed
Redirect request. RelayState, browser and invite bearers are stored as digests;
the request ID is separately encrypted and bound to tenant/provider/revision.

`POST /saml/{slug}/callback` is an SP-initiated browser ACS, not a JSON mutation:

- It accepts only `application/x-www-form-urlencoded`, at most two MiB, with
  exactly one `SAMLResponse` and one `RelayState`. Query parameters, compressed
  bodies, repeated parameters or additional fields are refused.
- It requires the one-use browser-bound receipt and the dedicated cookie. It
  does not require the cross-site IdP Origin to equal the console Origin.
- A matching receipt is consumed before signature/assertion verification and
  cannot be restored by a failed assertion. A wrong browser cannot consume it.
- Shared authcore verifies signature, issuer, audience, destination, request,
  time bounds and replay. Identity uses a persistent issuer/SP-scoped NameID;
  unsolicited IdP-initiated login is refused.
- The exact configured signed mail attribute is used for invitation admission.
  SAML has no OIDC `email_verified` claim requirement. A matching email alone
  cannot attach an existing account or create an uninvited user.
- Final admission rechecks current provider revision and active account, retaining
  invitation restrictions and atomic identity/session/audit updates.
- Success sets the normal Lax session cookie and returns `303 /`. Failure returns
  `303 /login?error=sso_failed`; raw assertions/upstream diagnostics never enter
  the response or audit. A consumed binding is cleared without clearing a newer
  binding from a stale callback.

See [SAML admission](../deploy/saml-login.md) and the separate actual
[Keycloak deployment evidence](../deploy/validation-keycloak-saml.md). Synthetic
management-page navigation does not establish signed IdP or SQL admission.

## 8. Audit log and traffic

**Reserved:** neither endpoint below has a Web handler. These are design
proposals, not current responses. The implemented read-only
[`doctor --audit`](../deploy/audit-chain.md) is a separate CLI operation and does
not expose an audit-list HTTP API or traffic counters.

### `GET /audit`

Admins see every entry; members see entries about themselves and their own
devices.

- Filters: `?action=`, `?device_id=`, `?user_id=` (admin only), `?since=`,
  `?until=`.
- Response: a paginated list of
  `{ "id", "created_at", "actor_type": "user|system|device", "actor", "action", "target_device_id", "client_ip", "details" }`.
- `details` never contains secrets.
- For members, `client_ip` is omitted unless the actor is the caller. A member
  does not learn an admin's address from an entry about their own device.

### `GET /traffic`

Admin only. Request: `?month=2026-10`. Returns the relay traffic soft counter
per device and the monthly total for the instance (DESIGN §5, §6). The counter
is for visibility only; nothing is blocked.

```json
{
  "month": "2026-10",
  "total_bytes": 123456789,
  "devices": [{ "device_id": "…", "bytes": 12345678 }]
}
```

## 9. Error codes

| HTTP | `code`                   | Meaning                                                                                                      |
| ---- | ------------------------ | ------------------------------------------------------------------------------------------------------------ |
| 400  | `invalid_request`        | Malformed JSON, unknown field, or a field that fails validation                                              |
| 401  | `unauthenticated`        | No valid session                                                                                             |
| 401  | `invalid_credentials`    | Sign-in failed (deliberately generic)                                                                        |
| 403  | `forbidden`              | Signed in, but the role does not allow this action                                                           |
| 403  | `csrf_failed`            | Missing or wrong CSRF token, or a missing or foreign `Origin` where one is required                          |
| 404  | `not_found`              | The object does not exist, or the caller may not see it                                                      |
| 404  | `invite_invalid`         | The invite token is unknown, used, expired or withdrawn (deliberately generic)                               |
| 405  | `method_not_allowed`     | The route does not accept this HTTP method; see Allow                                                        |
| 409  | `device_revoked`         | The action needs a device that is not revoked                                                                |
| 409  | `last_admin`             | The change would leave no active admin                                                                       |
| 409  | `last_local_admin`       | The change would leave no active admin with a local password                                                 |
| 409  | `user_exists`            | A user with this email already exists                                                                        |
| 409  | `slug_taken`             | Another provider already uses this slug                                                                      |
| 409  | `provider_in_use`        | Users are still bound to this provider (blocks deletion and issuer changes)                                  |
| 409  | `provider_changed`       | Concurrent provider revision changed; reload before another edit                                             |
| 409  | `already_signed_in`      | Sign out before beginning another SSO flow                                                                   |
| 409  | `device_not_revoked`     | Manual disconnect requires an already revoked device                                                         |
| 404  | `provider_unavailable`   | Invitation restriction refers to an unavailable provider                                                     |
| 401  | `sso_failed`             | SSO start could not be admitted; no upstream reason is exposed                                               |
| 422  | `saml_metadata_invalid`  | Trusted metadata could not pass the configured SAML policy                                                   |
| 503  | `sso_unavailable`        | No configured backend can start the selected protocol                                                        |
| 413  | `payload_too_large`      | A JSON body exceeds its route limit; normally 64 KiB                                                         |
| 415  | `unsupported_media_type` | An ordinary JSON API request has unsupported content type/encoding                                           |
| 422  | `weak_password`          | The new password does not meet the password policy                                                           |
| 422  | `oidc_discovery_failed`  | The issuer's discovery document could not be fetched or is invalid                                           |
| 429  | `rate_limited`           | Too many attempts; see `Retry-After`                                                                         |
| 500  | `internal`               | Operation unavailable; diagnostics expose only a fixed operation category, not raw database/upstream details |

## 10. Decisions and remaining work

Current implementation preserves these decisions:

- D18 separates the configured console hostname and device wildcard. Authz
  refuses custom domains and device use of the console host.
- D15 creates the first local administrator through a one-shot CLI operation;
  Web has no owner credential or first-admin HTTP endpoint.
- D7 grants an exact server-resolved source IP for 30 minutes only after explicit
  Open. Reads and background traffic cannot renew that grant.
- D6 rejects Ping/Login/NewProxy together after revocation. The heartbeat settings
  are 10/30 seconds; measured failure/hang and installed revoke timing are not an
  instantaneous all-stream cutoff guarantee.
- D19 uses an independent console HTTPS address input and token input.
- Shared authcore handles OIDC and SAML protocol verification; durable flow,
  invitation and account policy remain NetHub's tenant-bound operations.

Remaining work includes the reserved HTTP routes above, linking extra identities
into an existing account, traffic soft counters, operational credential rotation,
other doctor checks, scheduled database backups and full clean-host restoration.
Public-provider, native mobile/Open, revoke timing comparison, friend deployment,
disclosure and formal/canary release gates remain open. Accepted isolated SQL,
synthetic pages, two-Dex or Keycloak flows do not complete all W5-W7 requirements.
