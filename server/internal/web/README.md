# Console HTTP API

W3 implements health, local login/logout/session, device listing, and enrollment
token issuance. See the [API contract](../../../docs/console-api.md). React assets,
first-admin creation, complete Compose/Caddy startup, and browser acceptance are
the next steps; this API stage does not complete W3.

The server binds to one configured origin and a startup-selected tenant. Requests
cannot choose a tenant or role. It resolves client IP only through explicit
trusted proxy prefixes, warns on ignored forwarding headers, and applies bounded
login/enrollment budgets. All routes receive CSP, COOP, nosniff, referrer/HSTS
protection, and no-store. HSTS excludes includeSubDomains so device self-signed
TLS behavior is unaffected.

Pre-login Origin, authenticated CSRF, cookie ambiguity, JSON media/schema/size,
UTF-8, repeated JSON keys, pagination, and method checks run before operations.
The handler has a ten-second context budget; the CLI adds header/body/write/idle
timeouts and graceful shutdown. It opens only nethub_web credentials, refuses an
ambiguous multi-tenant database, and defaults to a loopback listener. Containers
must explicitly configure the private listener and Caddy's trusted address.

Successful login, logout, and enrollment issuance share a transaction with their
audit append. Audit failure rolls back the mutation; a failed login never emits
a cookie or token. Invalid-credential attempts admitted by the login budget use
an anonymous actor and record source IP only. JSON/CSRF/rate rejections append no
audit row. Neither application nor audit logs contain credentials, raw database
diagnostics, cookies, CSRF values, or enrollment tokens.

Device reads select explicit display columns, filter by the enabled actor's
current database role, and reapply tenant/ownership rules on every cursor page.
Links derive from the configured DNS domain and port 8443; a reserved console
hostname cannot be returned as a device URL. Online is a recent 45-second authz
observation, not a GUI health probe. W4 still supplies real observation data.

Unit tests cover request rejection, secure responses, CSRF/cookie separation,
rate budgets, proxy warnings, safe URL construction, and sanitized failures.
The isolated PostgreSQL suite starts a real TLS HTTP server, signs in member and
admin clients with cookie jars, checks pagination/tenant/owner boundaries, issues
and consumes a token exactly once, exercises disabled sessions and logout, and
revokes audit permission to prove atomic rollback of all three mutations.

Run Go tests from server/ and `sh tests/postgres.sh` for the genuine database
suite. Native evidence is in [the database validation record](../store/validation.md).
