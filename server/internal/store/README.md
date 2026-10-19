# Database foundation validation

This stage implements role bootstrap, embedded Goose migrations, forced tenant
RLS, device column grants, one-way revocation, concurrent single-use enrollment,
scoped Open/cutoff functions, serialized audit append, and a database-enforced
last-local-admin counter. The device store applies tenant context transactionally
and derives member/admin access from the enabled actor record.

`nethub migrate --password-file ...` uses only the dedicated migration role.
Passwords are read from files; connection errors omit DSNs and child output.
The PostgreSQL bootstrap is a separate superuser-only initialization script.
It reads the four mounted role passwords inside PostgreSQL, without placing
plaintext in argv or generated SQL source, and grants the backup read role there.

Run `sh server/tests/postgres.sh` from the repository root (Docker, Go, and
OpenSSL required). The harness creates random disposable credentials and a
PostgreSQL 16 container with no external network or published ports. It executes
the real initialization hook, migrations twice, and the Go integration test;
then re-executes bootstrap and removes its own container/anonymous volume.
A precompiled Linux test binary can be supplied with
`NETHUB_DATABASE_TEST_BINARY=/absolute/path/database.test`.
The harness also builds the Linux CLI for a real authz startup/enrollment/shutdown
test. A precompiled invocation must additionally supply
`NETHUB_AUTHZ_TEST_BINARY=/absolute/path/nethub`. Both executables and the shared
protocol fixtures are copied into the isolated test container; no host ports
are published.

The Compose development file publishes PostgreSQL only on workstation loopback.
It expects pre-generated service-specific files under the ignored
`deploy/secrets/postgres` directory, owned by the image's postgres UID with mode
0600. The init wizard prepares service-separated deployment secrets.
Do not use the disposable harness credentials for deployment. Existing database
volumes do not rerun image entrypoint scripts; migration and credential rotation
are explicit operations.

These migrations deliberately refuse automatic down migration. Back up before
production changes and restore a verified backup for rollback. PostgreSQL 16's
[RLS semantics](https://www.postgresql.org/docs/16/ddl-rowsecurity.html) and
[privileged function rules](https://www.postgresql.org/docs/16/sql-createfunction.html)
are the reference for the actual-role negative tests. A compromised web process
can still exercise its granted console authority; member isolation is application
store policy, not a claim that tenant RLS protects against compromised web SQL.

SAML/OIDC HTTP flows and persistent SAML replay storage remain W6 work. W3 console,
initialization, first-admin and scoped doctor deployment evidence is recorded in
deploy/validation-w3.md. Enrollment runtime coverage does not prove complete relay
authorization, production authz Compose wiring or appliance enrollment acceptance.

The tenant-bound AuthStore now supplies the local password/session service.
Login rechecks the verified password and active user under a user-row lock.
Session lookup locks user then session in separate statements before checking
current-time expiry; a single UPDATE can evaluate expiry before a blocking lock
wait. Actual PostgreSQL regressions cover both user-row and session-row waits.
Every lookup reloads role/disable state; logout deletes the persisted session.
