# Console invitations

The W6 backend implements invitation administration, inspection and local-password
acceptance. The administrator controls and `/invite` acceptance page are not yet
implemented. The returned fragment URL describes that planned page; this is not
a complete invitation or SSO flow, and W6 acceptance remains open.

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
the user can explicitly sign in with their chosen local password. The future page
must explain uncertain outcomes rather than automatically resubmitting a claim.

## Validation scope

Service/HTTP tests cover password policy, shared worker limits, session/CSRF
binding, cookie privacy, origin/CSRF, role scope, request validation and error paths.
The genuine PostgreSQL suite checks 72-hour hash-only grants, concurrent single
use, mailbox competition, provider restrictions, email-takeover refusal,
audit/session rollback, expiry after row and mailbox waits, live actor/provider
changes after observed lock waits, and HTTPS session activation. Hosted execution
and actual logs must pass before merging. These tests do not establish browser
invitation UI, real provider login or combined deployed W6 acceptance.
