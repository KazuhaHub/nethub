# Local console authentication

This package implements the W3 password/session service and HTTP policy helpers.
The HTTP endpoints and browser wiring are the next step; these checks alone do
not provide a working console login.

Passwords use Argon2id (19 MiB, two iterations, one lane), a random 16-byte salt,
and a 32-byte digest in PHC format. The parameters follow the
[OWASP password-storage recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
Verification bounds memory, iterations, salt, digest, and input lengths before
allocation. Stored parameter increases are supported within explicit limits;
changing the algorithm or those limits requires an implementation update.
The service permits two concurrent verifications; excess work returns ErrBusy.
Unknown users, SSO-only users, disabled users, and incorrect passwords return the
same error. Missing or malformed hashes pay a normal dummy verification cost.

Each login creates a fresh 32-byte random bearer. Only its SHA-256 digest is
persisted. Cookies use __Host-nethub_session, Secure, HttpOnly, SameSite=Lax,
Path=/, and no Domain. Ambiguous duplicate cookies are rejected. No bearer is
serialized in a login JSON response.

The per-session CSRF token is HMAC-SHA256 keyed by the bearer with a fixed
domain-separated label. Only the CSRF digest is stored. This lets GET /session
recover the same synchronizer token from the HttpOnly cookie without storing
either raw secret or adding a deployment-wide session key. The CSRF token cannot
serve as a bearer. Pre-login mutations require an exact configured HTTPS Origin;
authenticated mutations require the synchronizer header and reject any foreign
Origin. The HTTP layer must apply these helpers together, plus JSON/body limits.

Default timeouts are 30 minutes idle and 12 hours absolute, as permitted by PLAN.
The PostgreSQL repository reloads active user/role state on every request and
checks expiry only after acquiring user and session locks. Bookkeeping updates
last_seen_at without extending absolute expiry or any device access grant.
Session creation rechecks the verified password under a user lock, closing the
password-change/disable race during Argon2 verification. Logout deletes the row.

Login attempts have separate process-local fixed windows: ten per IP and five
per normalized account per minute. IPv4-mapped addresses share the IPv4 budget.
Each map holds at most 10,000 keys; capacity exhaustion refuses new keys until
expiry rather than evicting live counters. This is temporary throttling, not a
persistent account lock. Restart clears these budgets; replicas would need a
shared limiter before claiming an instance-wide bound. HTTP maps RateLimitError
and ErrBusy to bounded retry responses without exposing account existence.

The clientip package trusts X-Forwarded-For only from configured proxy prefixes,
walks the chain from right to left, and stops at the first untrusted address.
Forwarding headers from an untrusted socket peer are ignored and reported for
warning logging. The future HTTP server must wire that warning and use the
resolver result for login budgets and audit data.

Tests cover malformed and oversized PHC parameters, salts, wrong passwords,
cookies, token separation, duplicate cookies, exact origins, spoofed chains,
both limiter budgets, capacity/concurrency, repository errors, and worker limits.
The isolated PostgreSQL suite covers actual web/authz roles, tenant separation,
password-check races, live role/disable changes, idle/absolute expiry, expiry
during user/session lock waits, and logout. Browser/API acceptance remains open.
