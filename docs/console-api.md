# NetHub console API (draft)

> **Status: draft, written 2026-10-16 against design v0.3. Not implemented.**
> This is the planned JSON API between the React console and `nethub web`.
> Paths, field names and error codes are proposals: they are meant to be
> built against and revised, not relied on. When the code lands, this document
> must be updated in the same pull request as any change to the API.
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

- Base URL: `https://<console host>/api/v1/console`. Which host the console
  uses is a deployment decision (open, see [§10](#10-open-items)).
- Requests and responses are JSON (`Content-Type: application/json`, UTF-8).
  Request bodies larger than 64 KiB are rejected with `413`.
- Timestamps are RFC 3339 strings in UTC, for example `"2026-10-16T08:00:00Z"`.
- IDs are UUID strings.
- Unknown fields in a request body are rejected (`400 invalid_request`) rather
  than ignored.

### Authentication

- The console uses a **server-side session**. After sign-in the server sets a
  cookie named `__Host-nethub_session` (proposed), with `HttpOnly`, `Secure`,
  `SameSite=Lax`, `Path=/` and no `Domain` attribute.
- The `__Host-` prefix matters here. Device pages are served on sibling
  subdomains (`<subdomain>.router.example.com`) whose content is controlled by
  whoever owns the device, and the prefix stops them from setting or
  overriding the console's cookies.
- The short-lived OIDC flow cookie is also a `__Host-` cookie, with
  `SameSite=Lax`, which the provider's redirect back to the console needs.
- The cookie holds an opaque random token. The database stores only its hash.
- Sessions have an idle timeout and an absolute timeout, and can be revoked
  (DESIGN §6).
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
- **`GET` requests never change state**, with one exception:
  `GET /oidc/{slug}/callback`. That endpoint is protected by `state` plus the
  flow cookie.

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

### Audit

Endpoints marked **audited** write an entry to `audit_log`. The entry records
the acting user, the client IP and the target. It never records secrets.

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
| `POST /devices/{id}/cut-now` | admin (open, see §10) | W5 | yes |
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
  "cluster_hint": false,
  "online": true,
  "last_seen_at": "2026-10-16T08:00:00Z",
  "enrolled_at": "2026-10-01T12:00:00Z",
  "revoked": false,
  "revoked_at": null,
  "owner": { "id": "1f6c…", "email": "admin@example.com" }
}
```

- `online` is derived from `last_seen_at`, which `nethub authz` maintains
  from the relay. `nethub web` never queries `frps`. Being online means the
  device has a live tunnel, not that the OPNsense GUI itself is healthy
  (DESIGN §12).
- `owner` is included for admins. For members it is always themselves.
- The exact column list is settled with the data model (DESIGN §6). Hash and
  claim columns are never exposed.

### `GET /devices`

Lists devices. Admins see all devices; members see only their own.

- Optional filters: `?online=true|false`, `?revoked=true|false`.
- Response: a paginated list of device objects.

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

Response `200`: `{ "url": "https://abcd1234.router.example.com:8443" }`.

The console opens it in a new tab with `noopener,noreferrer`, so the device
page cannot reach the console tab. It also shows the hostname, so the user
can check where they are going. This is the user's only defence if the
console itself is compromised.

- If the source-IP gate is adopted (DESIGN §14 Q7, open), this call also
  registers the caller's client IP for this device for 30 minutes, and the
  response adds `"gate_expires_at"`.
- Without the gate, this endpoint only returns the URL. It exists so the gate
  can be added without changing the console.
- Errors: `409 device_revoked`.

### `POST /devices/{id}/revoke`

Marks the device revoked. Request: `{}`. Response: the updated device object.

- Revocation is one-way in the recommended design: a revoked device must
  re-enroll (DESIGN §6; open).
- The relay stops accepting the device on its next login or proxy
  registration.
- How a **live** tunnel is cut is not settled yet (DESIGN §5), so the API
  promises no cut-off time.

### `POST /devices/{id}/cut-now`

The manual "confirmed stolen, cut now" bypass (DESIGN §5).

- It requires the device to be revoked already.
- `nethub web` only records the request. `nethub authz` carries it out,
  because only authz holds the relay credentials.
- Response `202`: `{ "requested_at": "…" }`.
- Who may call it, and where the request is stored, are open (§10).

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
- The token's format may carry the console address, depending on an open
  decision (§10). In that case the plugin must show the address and ask the
  user to confirm it before enrolling. A crafted token could otherwise point
  the device's tunnel at an attacker's relay.
- To return `expires_at`, the web role needs `SELECT` on some
  `enroll_tokens` columns, which DESIGN §6 does not yet grant (§10).
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

### `PATCH /users/{id}`

Admin only. Request: any of `{ "role": "admin" | "member", "disabled": true | false }`.

- Disabling a user revokes all of their sessions immediately.
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

## 10. Open items

These decisions change the API. The design-level ones are tracked in
DESIGN §14.

- **Console host.** Is the console at the apex of the device wildcard domain,
  or on a subdomain? If it is under the wildcard, that label must be reserved
  so it is never assigned to a device.
  - Whatever the answer, no device may ever serve the console's hostname on
    port 8443. Cookies are not scoped by port, so such a device would receive
    the console's cookies.
  - frps 0.71.0 itself accepts custom domains that are not below
    `subDomainHost`. So authz must reject every `NewProxy` request with any
    custom domain (DESIGN §5).
- **First admin.** DESIGN decides that `nethub init` creates it (decision #8,
  §7). What is unresolved is how `init` reaches the database before
  `docker compose up` and the migrations have run. Either way it is a CLI
  action, not an API endpoint.
- **Enroll token format.** Does the token carry the console address, or does
  the plugin ask for it separately? This affects `POST /enroll-tokens`.
- **Source-IP gate** (DESIGN Q7): whether `POST /devices/{id}/open` registers
  the caller's IP, the window length, and whether it extends on use.
- **Live cut-off** (DESIGN §5): the mechanism behind `cut-now`, who may call
  it, and where the request is stored.
- **One-way revocation and the remaining grants** (DESIGN §6): whether
  un-revoking is impossible, and which tables the web role may write for
  `cut-now`, the gate, and pending enroll tokens. Listing or withdrawing
  pending enroll tokens is not in this draft because the web role has no
  `SELECT`/`DELETE` design for them yet.
- **Invite details:** the lifetime (72 hours proposed), and whether an invite
  can be restricted to one provider.
- **Linking an OIDC identity to an existing user.** DESIGN only binds
  identities to new users through invites. How a user who already has a
  local password adds an OIDC sign-in is not designed.
- **Grants the web role needs for this API.** `SELECT` on the `enroll_tokens`
  columns returned by `POST /enroll-tokens` (`id`, `created_by_user_id`,
  `created_at`, `expires_at`, `used_at`). This is to be added to DESIGN §6.
- **Password policy** for `weak_password`: minimum length and checks.
