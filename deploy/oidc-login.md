# OIDC browser admission

The backend implements the enabled-provider catalog, Origin-checked start and
GET callback routes described in the [console API](../docs/console-api.md).
Protocol processing directly uses `authcore/oidc`; NetHub owns browser binding,
durable one-use state and account/invitation admission. The sign-in page displays
enabled OIDC choices alongside local password access. Two-Dex deployment, a
public provider and SAML admission remain unfinished W6
work. These backend tests are not combined deployed SSO acceptance.

The public catalog loads independently of the password form; a catalog failure
does not prevent local emergency login. Starting SSO requires an explicit click.
The browser accepts only HTTPS authorization destinations without URL credentials
or fragments. Callback failures display one fixed message for `error=sso_failed`;
other query diagnostics are not rendered.

Administrators can restrict a new invitation to an enabled OIDC provider. The
claim page still erases the fragment before use, keeps the grant only in memory,
requires explicit logout of an existing account and sends the grant in the start
POST body. It never places the grant in an IdP URL or persistent browser storage.
Starting authorization does not consume the invitation or establish an account.

## Browser and protocol state

A start request creates independent random 32-byte state and browser bearers.
Only their hashes are persisted. Nonce, PKCE verifier and protocol configuration
binding are encrypted with the existing deployment key, a distinct
`oidc-flow-state` purpose and the authoritative tenant/flow ID. Invitation flows
store only the existing invitation digest. The raw invite never enters an
authorization URL, cookie or callback query.

State lasts five minutes according to the database clock. Its browser cookie is
host-only, Secure, HttpOnly, Path=/ and SameSite=Lax for the cross-site top-level
GET callback. HEAD is refused. Duplicate state parameters and duplicate flow
cookies are refused. Starting while already signed in requires explicit logout.
The start response exposes only the authorization URL; the browser bearer stays
in the HttpOnly cookie.

The callback locks provider before flow, checks tenant/slug/browser/revision and
post-lock expiry, then commits consumption before discovery or code exchange.
Consumption clears the encrypted protocol payload. A wrong browser cannot consume
the flow. Exchange, verification or account-admission failure does not revive it;
the caller starts a new authorization flow. There is no automatic code retry.
A stale callback that did not consume its flow does not clear a newer browser
binding. A provider error response consumes a matching flow without exchanging.

The shared module verifies signature, issuer, audience, expiry, state, nonce and
S256 PKCE. An optional authorization-response issuer must also match the selected
provider. Callback selection is bound to its recorded provider; identity lookup
uses the shared module's trusted canonical issuer and verified subject, including
its documented Google issuer compatibility.

Expired rows are removed on the next start. A short tenant-scoped insertion
lease caps unexpired rows, including consumed rows, at 10,000 across Web processes.
Expiry remains enforced while idle; expired encrypted rows may remain until the
next start. Start/callback attempt budgets are process-local and bound failure
audits as well as protocol attempts. This is not distributed traffic limiting.

## Account and invitation transaction

After protocol verification, SQL rechecks the current provider revision and
enabled state. A changed/disabled provider fences an already-consumed flow.
An issuer/subject lease serializes competing identity bindings. A previously
bound active user can sign in without a verified-email claim, through another
enabled configuration for the same issuer. A changed email claim never relinks
or edits that account. Disabled bound users are refused.

An unbound subject needs the invitation from this flow. Its signed email must
match the normalized invited email and `email_verified` must be JSON true;
strings, false, null and absent values are not true. The transaction rechecks
restriction, cancellation, unused state and expiry after invitation/mailbox waits.
An existing mailbox is refused, even when the email claim is verified. The
original inviter need not still be an administrator, matching local invitation
activation policy.

Account, identity, session, invitation consumption, admission receipt and audits
commit atomically. New SSO accounts have no local password. The existing local
emergency-administrator guard is unchanged. A failed admission rolls these writes
back while preserving prior flow consumption. If a successful reply is lost,
the user explicitly starts a normal SSO flow; the existing subject binding can
sign in without reusing the consumed invitation.

## Diagnostics and validation scope

Callbacks leave the authorization code/state query through a fixed redirect to
`/` or `/login?error=sso_failed`. Responses use no-store and no-referrer. Failure
audits store normalized source IP and a bounded reason category, never upstream
messages, authorization codes, state, cookies, nonce, verifier or tokens. The
bundled Caddy configuration does not enable access logging. External proxies
must redact or exclude callback queries if access logging is enabled.

Actual TLS tests use a signed test IdP to check shared verification, PKCE,
browser mismatch, strict verified-email decoding, eight concurrent callbacks and
one exchange after a lost reply. Their repository is an in-memory fixture.
HTTP tests separately check Origin, cookie attributes, duplicate/HEAD refusal,
safe redirects, audit budgets and signed-in-account protection.

Genuine PostgreSQL cases cover encrypted durable state and fresh-repository
restoration, role/RLS scope, cross-flow substitution, eight-way consumption,
provider changes, issuer/subject identity, invitation races, existing/disabled
accounts, real session/CSRF lookup and audit rollback. They observe actual lock
waits before checking flow/account and invitation/mailbox expiry. Their protocol
assertions are trusted fixtures; they do not establish IdP verification. Hosted
execution and actual logs are required before accepting these SQL boundaries.
