# Database boundary validation

On 2026-10-18, the actual PostgreSQL 16 image and initialization hook passed an
isolated native run on the designated development LXC. The test container had
network mode none and no published ports; existing services were not stopped.
Random temporary passwords stayed in files, and the container/anonymous data
volume were removed by the harness afterward.

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
