# Initial administrator bootstrap

After migrations, run `nethub admin create --email admin@example.com
--owner-password-file /run/secrets/pg_nethub_owner` in the separate one-shot
bootstrap service. The password is entered twice with terminal echo disabled.
This command is not available through HTTP. Do not run it inside the web runtime
or mount owner credentials into web.

Automation can add `--password-stdin` and supply a protected pipe or file redirect.
There is no plaintext password argument or environment variable. Avoid shell
commands containing password literals: those would become history/process data
before NetHub runs. One trailing LF/CRLF is removed; other whitespace is preserved.
Input is bounded to 1024 UTF-8 bytes and rejects embedded line endings and NUL.
The minimum is 15 characters for this initial local-password account, following
the [OWASP baseline without MFA](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
Additional password-change and invitation controls remain W6 work.

The database operation verifies the isolated nethub_owner role, requires exactly
one tenant and no existing accounts, and serializes against other account writes.
The new Argon2id account, local-admin counter, and admin.bootstrap audit append
commit together. Repeating the command refuses to reset credentials or create
another administrator. Existing deployments must use future account-management
or explicit operator recovery procedures; this is only a first-account tool.

Unit tests cover input bounds, Unicode, preserved whitespace, malformed data,
configuration rejection, and credential-free diagnostics. Real PostgreSQL tests
cover runtime-role rejection, audit rollback, four concurrent bootstrap attempts
with exactly one success, repeat rejection, hash verification, normal login/logout,
and audit-secret exclusion. Hidden interactive terminal entry is implemented with
golang.org/x/term; complete one-shot Compose execution and deployed browser login
will be verified with the remaining W3 deployment work.
