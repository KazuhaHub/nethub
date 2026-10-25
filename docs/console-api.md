# NetHub console API (draft)

> **Status: partially implemented, updated 2026-10-24 against design v0.3.**
> W3 implements health, local login/logout/session, device listing, and enroll-token
> issuance through `nethub web`. The React console implements these W3 flows;
> W4 deployment acceptance is recorded separately. W5's scoped Open API is
> implemented with NewUserConn enforcement in generated relay bundles. Open,
> Revoke and disconnect UI/API are implemented; combined native/public W5 acceptance
> remains pending. Other W5-W7 console endpoints below
> remain proposals.
> Update this document in the same pull request as any API contract change.
> [`DESIGN.md`](DESIGN.md) is the authority on behaviour; where this document
> and DESIGN disagree, DESIGN wins.

## Contents

- [1. Scope](#1-scope)
- [2. Conventions](#2-conventions)
- [3. Endpoint summary](#3-endpoint-summary)
- [4. Session and sign-in](#4-session-and-sign-in)
- [5. Devices and enroll tokens](#5-devices-and-enroll-tokens)
- [6. Users and invites](#6-users-and-invites)
- [7. OIDC providers](#7-oidc-providers)
- [8. Audit log and traffic](#8-audit-log-and-traffic)
- [9. Error codes](#9-error-codes)
- [10. Open items](#10-open-items)

## 1. Scope

Covered: everything under `/api/v1/console/`, served by `nethub web` and
called by the console in the browser, plus the browser redirects of the OIDC
flow and a health check.

Not covered:

- the **device API** (`/api/v1/devices/*`: enroll, rotate, unenroll, status),
  served by `nethub authz` and defined in [`proto/`](../proto/README.md);
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
  Request bodies larger than 64 KiB are rejected with `413`.
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
- The short-lived OIDC flow cookie is also a `__Host-` cookie, with
  `SameSite=Lax`, which the provider's redirect back to the console needs.
- The cookie holds an opaque random token. The database stores only its hash.
- Sessions have an idle timeout and an absolute timeout, and can be revoked
  (DESIGN §6). Initial defaults are 30 minutes idle and 12 hours absolute.
  Current active-account and role state is reloaded from PostgreSQL on each request.
- A request without a valid session gets `401 unauthenticated`. The console
  then sends the user to the sign-in page.

### CSRF

- **Requests with a body** must use `Content-Type: application/json`. Anything
  else gets `415 unsupported_media_type`. This also stops plain HTML form posts.
- **Endpoints called before sign-in** must carry an `Origin` header equal to
  the console's own origin. A missing or foreign `Origin` gets
  `403 csrf_failed`. These endpoints are `POST /login`, `POST /invites/inspect`,
  `POST /invites/accept` and `POST /oidc/{slug}/start`.
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

| Role | Can |
|---|---|
| `admin` | Everything below, for all devices and users in the instance |
| `member` | Their own devices and enroll tokens, their own audit entries, their own account |

A member asking for someone else's device gets `404 not_found`, not `403`, so
the API does not reveal that the device exists.

### Errors

Every error response has this shape:

```json
{ "error": { "code": "invalid_request", "message": "label must be at most 64 characters" } }
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

**HSTS.** If the console sits at the apex of the device domain, its HSTS
header must **not** use `includeSubDomains`. Doing so would stop browsers
from letting users click through the device certificate warning, which v1
depends on (self-signed device certificates).

### Secrets never come back

- Enroll tokens and invite links are shown **once**, in the response that
  creates them.
- OIDC client secrets are write-only.
- No response ever contains a password hash, session token, device secret,
  domain claim or any `*_hash` column.

### Rate limits

These endpoints are rate limited per client IP and, where there is one, per
account:

- `POST /login`
- `POST /me/password`
- `POST /invites/inspect`
- `POST /invites/accept`
- `POST /oidc/{slug}/start`
- `POST /enroll-tokens`

A limited request gets `429 rate_limited` with a `Retry-After` header.

Per-account limiting slows attempts down. It never locks the account:
otherwise anyone who knows the break-glass admin's email could lock that
admin out.

The client IP is taken from `X-Forwarded-For` only when the request comes from
the declared trusted proxy (Caddy); DESIGN §6.

W3 login and enroll issuance have separate process-local windows: ten attempts
per source IP and five per normalized account/user per minute. Each counter map
holds at most 10,000 live keys; new keys fail closed at capacity until expiry.
Password work also has a two-verification concurrency bound, with Retry-After: 1
when busy. These limits are for the single-process deployment, not replica-wide.

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

| Method and path | Who | Phase | Audited |
|---|---|---|---|
| `GET /healthz` (outside the API prefix) | anyone | W3 | no |
| `POST /login` | anyone | W3 | yes |
| `POST /logout` | signed in | W3 | yes |
| `GET /session` | anyone | W3 | no |
| `POST /me/password` | signed in, local password | W6 | yes |
| `GET /oidc/providers` | anyone | W6 | no |
| `POST /oidc/{slug}/start` | anyone | W6 | no |
| `GET /oidc/{slug}/callback` (browser redirect) | anyone | W6 | yes |
| `GET /devices` | admin: all; member: own | W3 | no |
| `GET /devices/{id}` | admin, or owner | W4 | no |
| `PATCH /devices/{id}` | admin, or owner | W4 | yes |
| `POST /devices/{id}/open` | admin, or owner | W5 | yes |
| `POST /devices/{id}/revoke` | admin, or owner | W5 | yes |
| `POST /devices/{id}/disconnect` | admin, or owner; already revoked | W5 | yes |
| `POST /enroll-tokens` | signed in | W3 | yes |
| `GET /users` | admin | W6 | no |
| `PATCH /users/{id}` | admin | W6 | yes |
| `POST /invites` | admin | W6 | yes |
| `GET /invites` | admin | W6 | no |
| `DELETE /invites/{id}` | admin | W6 | yes |
| `POST /invites/inspect` | anyone holding an invite token | W6 | no |
| `POST /invites/accept` | anyone holding an invite token | W6 | yes |
| `GET /oidc-providers` | admin | W6 | no |
| `POST /oidc-providers` | admin | W6 | yes |
| `PATCH /oidc-providers/{id}` | admin | W6 | yes |
| `DELETE /oidc-providers/{id}` | admin | W6 | yes |
| `GET /audit` | admin: all; member: own | W7 | no |
| `GET /traffic` | admin | W7 | no |

All paths below are relative to `/api/v1/console` unless stated otherwise.

## 4. Session and sign-in

### `GET /healthz`

Served by `nethub web` on the internal network for the container health
check. Caddy does not route it from the internet (proposed: Caddy answers
`404` for `/healthz`).

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

Changes the caller's local password. Request:
`{ "current_password": "…", "new_password": "…" }`.

Response `204`. All of the user's other sessions are revoked.

Errors:

- `403 invalid_current_password`. This is not `401`, because the console
  treats `401` as "signed out".
- `422 weak_password`.
- `429 rate_limited`.

### OIDC sign-in

The flow follows DESIGN §6 and decision #22: authorization code with PKCE,
`state` and `nonce` kept server-side, identities bound by `(issuer, subject)`.

**`GET /oidc/providers`** lists the enabled providers for the sign-in page:

```json
{ "items": [ { "slug": "company-sso", "display_name": "Company SSO" } ] }
```

**`POST /oidc/{slug}/start`** begins a flow.

- Request: `{}` for an ordinary sign-in, or `{ "invite_token": "…" }` when the
  user arrived from an invite link (see [§6](#6-users-and-invites)).
- The server creates the flow record, which holds `state`, `nonce`, the PKCE
  verifier and, if present, the invite. It sets a short-lived flow cookie.
- Response `200`: `{ "redirect_url": "https://idp.example.com/authorize?…" }`.
  The console then navigates the browser to that URL.

This is a `POST` so the invite token travels in the body. It never appears in
a URL that could end up in access logs or browser history.

**`GET /oidc/{slug}/callback`** is the redirect URI registered at the
provider. It is a browser endpoint, not a JSON one.

- The server checks `state` against the flow cookie and exchanges the code
  using the PKCE verifier.
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
  "owner": { "id": "1f6c…", "email": "admin@example.com" }
}
```

- `online` means authz reported the tunnel within the last 45 seconds, derived
  from non-future `last_seen_at`. This is a recent observation subject to polling
  delay, not a real-time GUI health check. `nethub web` never queries `frps`.
  Authz observation wiring remains W4; W3 verifies this using isolated fixtures.
- `cluster_hint` is a nullable display string, matching the database model.
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

Returns one device object. `404 not_found` if it does not exist, or if the
caller is a member and does not own it.

This applies to every `/devices/{id}` endpoint below: the ownership check
comes first. A member asking about someone else's device always gets `404`,
before any other error such as `409`.

### `PATCH /devices/{id}`

Changes the display label. Request: `{ "label": "Branch office" }`.

- `label` is at most 64 characters.
- Nothing else is writable. Identity fields (subdomain, owner, claim) cannot
  be changed through the console by design (DESIGN §6).
- Response: the updated device object.

### `POST /devices/{id}/open`

Request: `{}` without query parameters. Response `200`:

```json
{ "url": "https://abcd1234.router.example.com:8443", "gate_expires_at": "2026-10-24T08:30:00Z" }
```

The API, transactional database grant and generated relay's NewUserConn checks
are implemented. Existing bundles must include NewUserConn in the frps callback
operation list. The console button and real native gate acceptance remain W5
work; an API response alone does not verify a successful GUI connection.

The console opens it in a new tab with `noopener,noreferrer`, so the device
page cannot reach the console tab. It also shows the hostname, so the user
can check where they are going. This is the user's only defence if the
console itself is compromised.

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

- Revocation is one-way in the recommended design: a revoked device must
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
  of those bytes. It accepts no owner/tenant/expiry override. The final device-side
  input format may carry the console address, depending on W4 decision D19.
  If the address is included, the plugin must show it and ask the
  user to confirm it before enrolling. A crafted token could otherwise point
  the device's tunnel at an attacker's relay.
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
  "identities": [ { "provider_slug": "company-sso", "linked_at": "2026-10-10T09:00:00Z" } ],
  "created_at": "2026-10-10T09:00:00Z"
}
```

### `GET /users`

Admin only. A paginated list of user objects.

The implemented backend accepts `limit` (1–200, default 50) and an opaque
`cursor`, returning `{ "items": [...], "next_cursor": null | "..." }`.
Passwords, hashes, identity subjects and provider secrets are never projected.
The user-management interface and invitation/SSO flows remain W6 work.

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
   provider and starts `POST /oidc/{slug}/start` with the invite token.

### `POST /invites`

Admin only. Request: `{ "email": "alice@example.com", "role": "member" }`.

Response `201`:

```json
{ "id": "…", "invite_url": "https://console.example.com/invite#…", "expires_at": "2026-10-19T08:00:00Z" }
```

- The lifetime is proposed at 72 hours (open, §10).
- Errors: `409 user_exists`.

### `GET /invites`

Admin only. Lists pending invites (`id`, `email`, `role`, `created_at`,
`expires_at`, `created_by`), never the token.

### `DELETE /invites/{id}`

Admin only. Withdraws a pending invite. Response `204`.

### `POST /invites/inspect`

Request: `{ "token": "…" }`.

Response `200`:

```json
{ "email": "alice@example.com", "role": "member", "expires_at": "…", "providers": [ { "slug": "company-sso", "display_name": "Company SSO" } ] }
```

Errors: `404 invite_invalid`, for an unknown, used, expired or withdrawn
token. These cases are deliberately indistinguishable. Also `429 rate_limited`.

### `POST /invites/accept`

Accepts with a local password. Request: `{ "token": "…", "password": "…" }`.

- Response `200`: same body as `POST /login`, with the session cookie set.
- Errors: `404 invite_invalid`, `422 weak_password`, `429 rate_limited`.

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
  (DESIGN §6).
- Response `201`: the provider object.
- Errors: `409 slug_taken`, `422 oidc_discovery_failed`.

### `PATCH /oidc-providers/{id}`

Any field of the create request except `slug`. Sending `client_secret`
replaces it; omitting it keeps the stored one. Response: the provider object.

`issuer_url` cannot be changed once any user is bound to the provider
(`409 provider_in_use`): bindings are by issuer.

### `DELETE /oidc-providers/{id}`

Response `204`.

- If users are still bound to the provider, deletion is refused with
  `409 provider_in_use`. Disable it instead (`"enabled": false`).
- Proposed: deleting a provider with no bound users also withdraws invites
  restricted to it, if invite restriction is implemented.

## 8. Audit log and traffic

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
{ "month": "2026-10", "total_bytes": 123456789, "devices": [ { "device_id": "…", "bytes": 12345678 } ] }
```

## 9. Error codes

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `invalid_request` | Malformed JSON, unknown field, or a field that fails validation |
| 401 | `unauthenticated` | No valid session |
| 401 | `invalid_credentials` | Sign-in failed (deliberately generic) |
| 403 | `forbidden` | Signed in, but the role does not allow this action |
| 403 | `csrf_failed` | Missing or wrong CSRF token, or a missing or foreign `Origin` where one is required |
| 403 | `invalid_current_password` | The current password given to `POST /me/password` is wrong |
| 404 | `not_found` | The object does not exist, or the caller may not see it |
| 404 | `invite_invalid` | The invite token is unknown, used, expired or withdrawn (deliberately generic) |
| 405 | `method_not_allowed` | The route does not accept this HTTP method; see Allow |
| 409 | `device_revoked` | The action needs a device that is not revoked |
| 409 | `last_admin` | The change would leave no active admin |
| 409 | `last_local_admin` | The change would leave no active admin with a local password |
| 409 | `user_exists` | A user with this email already exists |
| 409 | `slug_taken` | Another provider already uses this slug |
| 409 | `provider_in_use` | Users are still bound to this provider (blocks deletion and issuer changes) |
| 413 | `payload_too_large` | The request body exceeds 64 KiB |
| 415 | `unsupported_media_type` | A request body is not `application/json` |
| 422 | `weak_password` | The new password does not meet the password policy |
| 422 | `oidc_discovery_failed` | The issuer's discovery document could not be fetched or is invalid |
| 429 | `rate_limited` | Too many attempts; see `Retry-After` |
| 500 | `internal` | Unexpected error. The response contains no details; the server log has them |

## 10. Decisions and remaining work

Confirmed on 2026-10-18:

- D18 uses a separate configured console hostname and device wildcard. A device
  may never serve the console hostname on any port; authz must reject every
  custom domain during NewProxy validation.
- D15 runs init, Compose/migration, then a one-shot local admin-create command.
  Web never receives owner credentials; there is no first-admin HTTP endpoint.
- D7 enables source-IP gating for v1: Open grants 30 minutes; another explicit
  Open renews it. Reads and background traffic do not renew it.
- D6 uses 10-second heartbeats and a 30-second timeout, denying Ping/Login/NewProxy
  together for revocation. Backend failure and hanging-hook limits remain as
  measured in W0; the API does not promise instantaneous live disconnection.
- Device revocation is one-way. The database already enforces it, limits web's
  writes, and provides scoped Open/cutoff functions. The scoped Open HTTP API is
  implemented with generated relay source checks; revocation/cutoff HTTP
  integration, Open UI and native gate acceptance remain W5.
- Web's enrollment status-column grants are implemented. Hash read/expiry update
  and token consumption remain unavailable to web.
- SAML is included in v1 through authcore/saml; its complete HTTP flows, trusted
  metadata, persistent replay store, invitation binding, and browser request state
  are W6 alongside OIDC.

Still open for their implementation stages:

- D19: final device enrollment input format and console-address discovery.
- W5: cutoff endpoint role policy and authz processing of stored cutoff requests.
- W6: invitation/provider restriction workflows, linking additional identities
  to an existing account, and the password-policy checks behind weak_password.
- Browser, init/admin, Compose/Caddy health isolation, backup, and complete
  deployment acceptance are not proved by the W3 HTTP tests.
