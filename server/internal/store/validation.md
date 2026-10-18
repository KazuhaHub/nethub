# Database boundary validation

On 2026-10-18, the actual PostgreSQL 16 image and initialization hook passed an
isolated native run on the designated development LXC. The test container had
network mode none and no published ports; existing services were not stopped.
Random temporary passwords stayed in files, and the container/anonymous data
volume were removed by the harness afterward. A separate final check found zero
remaining test containers; four owned upload stages were archived privately before
removal.

The two embedded Goose migrations applied successfully and a second application
was a no-op. Re-running the real role bootstrap succeeded with the same files.
Ten live boundary groups passed:

1. Non-superuser runtime roles, forced RLS on all twelve tenant tables, and rejection
   of web as a migration role.
2. Tenant filtering, transaction-local context cleanup, member ownership, admin
   visibility, and rejection of a foreign-tenant actor.
3. Forbidden device identity/hash writes and reads, device deletion/insertion,
   unauthorized token consumption, direct grant/request mutation, cross-process
   user access, and cross-tenant foreign keys. Backup writes were denied.
4. Eight concurrent consumers of one enrollment token produced exactly one winner.
5. Real pg_dump using the backup role included both tenant fixtures without write
   authority. Its password was supplied through a protected temporary PGPASSFILE.
6. Expired tokens and disabled creators were rejected; web could not extend expiry.
7. Open/cutoff functions checked actor/device ownership, rejected network ranges,
   and assigned a fixed thirty-minute grant.
8. Both web and authz were unable to reverse device revocation.
9. Audit append linked consecutive entries; runtime update/delete was denied.
10. Two concurrent admin disables produced one success and retained a local admin.

Password-file bounds and forbidden-role/TLS-downgrade unit cases also passed.
The first bootstrap attempt rejected trailing newlines because PostgreSQL btrim
removes spaces by default; explicit CR/LF trimming fixed it. A PL/pgSQL CASE
expression then exposed a parser ambiguity and was parenthesized. Both failed
observations and successful logs are retained privately. Neither failure was
accepted as a passing database check.

This validates the database foundation, not W3 completion. The browser/API auth,
initial admin CLI, deployed secret preparation, full Compose startup, and SAML/OIDC
login still require implementation and their own acceptance checks.
# Local authentication follow-up (2026-10-18)

The isolated PostgreSQL suite now includes local password login, normalized email,
generic unknown/wrong/disabled credential failure, persisted bearer/CSRF digests,
tenant isolation, current role state, immediate disabled-account rejection,
password changes and disable during verification, idle/absolute expiry, and
logout of an active session. The authz role still cannot read console credentials.

A new regression initially failed: a session that expired during a user-row lock
wait was accepted by a single UPDATE with a materialized actor CTE, even with
clock_timestamp() predicates. The implementation now obtains user then session
locks in separate statements and checks expiry afterward. Both lock-wait cases
pass on genuine PostgreSQL 16. The final local run passed all eleven boundary
groups in 1.99 seconds. Private logs retain the failed and corrected attempts.
HTTP endpoints, browser acceptance, and complete Compose startup remain open.

## Console HTTP follow-up (2026-10-18)

The genuine PostgreSQL suite now passes twelve boundary groups, including a real
TLS HTTP server with member/admin cookie-jar clients. It verifies login/session,
ownership and tenant-filtered cursor pagination, display-only device data, JSON
expiry-override rejection, source-IP audit data, single-use HTTP-issued enrollment
tokens, token throttling, logout, and disabled-account rejection. Revoking audit
EXECUTE permission caused login, logout, and issuance to fail without persisting
partial mutations or emitting credentials. Restoring permission recovered them.
The native run passed in 3.63 seconds; private logs retain the run. This tests the
server handler and actual role credentials, not complete Compose/browser startup.

## Initial administrator follow-up (2026-10-18)

Thirteen genuine PostgreSQL boundary groups passed in 3.40 seconds, including
owner-only bootstrap on the freshly migrated single tenant. An audit rejection
rolled back both the user and local-admin counter. Four concurrent requests
produced exactly one administrator; subsequent attempts refused creation. The
stored Argon2id hash verified and the new account passed normal login/logout.
Web/authz roles were rejected and the bootstrap audit omitted credential material.
This covers the database operation; the actual one-shot Compose service and
interactive deployment flow remain acceptance work.
