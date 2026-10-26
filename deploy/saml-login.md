# SAML browser admission

PR #180 was accepted at final source `1904080a2545` and merged as `2503ab23ea2e`.
All six jobs in run `40397477218`, actual logs, inherited gates, one DCO and both
final two-Dex regression images/hashes passed review. The tested and merged trees
match. This accepts the backend boundaries below; deployed signed SAML and
combined W6 acceptance remain separate requirements.

NetHub delegates SAML protocol processing to the shared module. The imported
`authcore/saml` package signs login requests, verifies and decrypts assertions,
checks the destination and request, and prevents assertion replay. Trusted
administrator metadata and the provider's encrypted signing identity are reused.
Expired metadata is refused; Redirect endpoints pass the deployment's HTTPS/DNS
policy before a request starts.

`GET /api/v1/console/saml/providers` lists enabled choices. A same-origin JSON
`POST /api/v1/console/saml/{slug}/start` accepts an optional invitation bearer
and returns the IdP redirect. Existing signed-in accounts must sign out first.
The five-minute PostgreSQL receipt stores digests of independent RelayState,
browser binding and invitation values. Only the request ID is stored in the
encrypted protocol payload, under a purpose distinct from OIDC and SP keys.
Tenant-scoped insertion/cleanup is serialized and capped at 10,000 records.

The dedicated `__Host-nethub_saml` browser cookie is Secure, HttpOnly, host-only
and `SameSite=None` so the IdP's cross-site form POST can return it. Ordinary
session and OIDC cookies retain their existing Lax policy.

The POST callback accepts only one `SAMLResponse` and one `RelayState`, with
bounded form input and no query parameters or additional fields. It does not
require the IdP's Origin to equal the console. A valid one-use browser-bound
receipt and authcore's cryptographic/request checks authorize this operation.
Consumption commits before assertion verification; a failed assertion cannot
restore the request. A stale callback cannot clear a newer browser binding.

Verified SAML identity uses the persistent issuer/SP-scoped NameID mapper.
Email comes from the exact configured signed Attribute Name. This is distinct
from OIDC's `email_verified` flag. The final session transaction selects a known
protocol's provider and consumed receipt, rechecks provider revision and active
account, and uses invitation-only new binding. Mailbox equality cannot attach an
existing account. A SAML identity also retains its provider scope. Invitation,
identity, session and audit changes commit together after a final expiry check.
The local-password emergency administrator remains independent.

Local service tests generate real RSA-signed XML and exercise success, wrong
issuer/audience/destination/request, expiry, browser mismatch and assertion/flow
replay. HTTP tests use an observer backend for form, cookie, Origin and privacy
boundaries; they do not establish signature or database acceptance. Genuine
PostgreSQL cases separately cover durable encrypted requests, tenant/browser
binding, concurrent consumption/admission, protocol/mail-purpose separation,
disabled accounts, RLS/role boundaries and capacity cleanup. Their hosted
execution is still required.

Sign-in/invitation page wiring, provider management pages, a deployed signed IdP,
normal-TLS browser acceptance and complete W6 acceptance remain unfinished.
