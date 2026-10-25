# Console invitations

The W6 backend implements invitation administration, inspection and local-password
acceptance. Administrators use `/invitations` to page through pending grants,
create a link and withdraw an invitation. Recipients use `/invite` to inspect a
grant and set a local password. Provider-bound invitations offer no password
fallback; their SSO launch controls remain separate W6 work. Combined deployed
W6 and SSO acceptance remain open.

## Administration and privacy

An active administrator can create a 72-hour invitation for an email and role,
optionally restricted to an enabled provider. Creation and withdrawal recheck
current authority while holding the actor row. Members cannot administer invites,
and tenant-bound stores cannot inspect or consume another tenant's token.

The bearer contains 32 random bytes. PostgreSQL receives only its SHA-256 digest;
plaintext is returned once within `https://console.example.com/invite#<token>`.
Pending pages contain metadata and creator identity, never bearer/digest material.
There is no outbound email. Withdrawal preserves its first cancellation and audit
on an exact retry. A grant remains valid until used, withdrawn or expired; later
changes to its creator do not silently withdraw it.

Inspection and acceptance require a matching HTTPS console Origin and bounded
JSON bodies. Their independent process-local attempt budgets are ten per IP and
five per token digest per minute, with bounded maps. Login and invitation hashing
share the same two-worker budget. Passwords use the existing bootstrap policy:
at least 15 Unicode characters, at most 1024 UTF-8 bytes, without CR/LF/NUL.

## Atomic acceptance

Acceptance locks the invitation and its tenant/mailbox creation lease. The consume
statement checks validity after both waits using the database clock. The same
transaction consumes the token, creates the account, inserts its first session and
appends invitation/login audits. Failure at any step rolls everything back.

An existing email never attaches an identity or changes an account. Concurrent
claims of one token or different tokens for one mailbox can create only one new
account. A provider-bound invitation cannot be claimed with a local password.
Inspection exposes only enabled provider names, slugs and kinds; SSO remains W6
work through the approved shared-module boundary.

Successful acceptance uses the ordinary session/CSRF construction and cookie
policy. Unknown, used, expired, withdrawn and locally forbidden claims return the
same `invite_invalid` response. A failed authentication audit must also succeed
before that denial response is returned. Audit payloads contain normalized source
IP and invitation row IDs, without bearer, password, session or hash material.

A lost response can leave a committed account/session without a delivered cookie.
The bearer remains consumed. This does not authorize replay or email-based login;
the user can explicitly sign in with their chosen local password. The page
explains uncertain outcomes, removes the claim form and offers ordinary sign-in
rather than automatically resubmitting a claim.

## Validation scope

Service/HTTP tests cover password policy, shared worker limits, session/CSRF
binding, cookie privacy, origin/CSRF, role scope, request validation and error paths.
The genuine PostgreSQL suite checks 72-hour hash-only grants, concurrent single
use, mailbox competition, provider restrictions, email-takeover refusal,
audit/session rollback, expiry after row and mailbox waits, live actor/provider
changes after observed lock waits, and HTTPS session activation. PR #170 passed
all six hosted checks with actual logs inspected. These database tests do not
establish browser invitation UI, real provider login or combined deployed W6
acceptance.


## Browser behavior and evidence

The entry point reads and erases a canonical fragment before rendering or making
API requests. Only the recipient component retains the bearer; it never enters
query parameters or browser storage. Reloading requires the original link again.
Inspection does not claim the invitation or replace an existing account session;
that account must be explicitly signed out before local activation.

Generated links are shown once, checked against the current HTTPS origin and
copied only on an explicit click. Closing the dialog clears its link. The pending
inventory uses explicit refresh instead of background requests that extend an
idle session. Creation and withdrawal block duplicate submission and dialog
closure while pending. Unconfirmed mutations require inventory review before
retry, and unconfirmed activation offers explicit password sign-in without replay.
Bodyless withdrawal still sends the current CSRF token.

Browser tests exercise production authentication and HTTP handlers with a
loopback-only in-memory repository, including a real accepted response discarded
before its cookie is delivered. The fixture is not the PostgreSQL boundary proof.
Only synthetic, secret-free inventory and empty-password recipient screenshots
and a boolean receipt are published; generated links, passwords and raw requests
are excluded. Hosted artifact review is required before browser acceptance.
