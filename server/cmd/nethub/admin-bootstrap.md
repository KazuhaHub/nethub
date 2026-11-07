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
[Invitations](../../../deploy/invitations.md) and
[user administration](../../../deploy/user-administration.md) have separate
implementations and validation scopes. This command does not reset passwords.

The database operation verifies the isolated nethub_owner role, requires exactly
one tenant and no existing accounts, and serializes against other account writes.
The new Argon2id account, local-admin counter, and admin.bootstrap audit append
commit together. Repeating the command refuses to reset credentials or create
another administrator. Existing deployments must use normal account management
or explicit operator recovery procedures; this is only a first-account tool.

Unit tests cover input bounds, Unicode, preserved whitespace, malformed data,
configuration rejection, and credential-free diagnostics. Real PostgreSQL tests
cover runtime-role rejection, audit rollback, four concurrent bootstrap attempts
with exactly one success, repeat rejection, hash verification, normal login/logout,
and audit-secret exclusion. Hidden interactive terminal entry is implemented with
golang.org/x/term. The accepted [W3 deployment record](../../../deploy/validation-w3.md)
includes one-shot Compose initialization and deployed browser login. Its dated
evidence does not complete later W5-W7 public/operator and release requirements.
