# Isolated host issuer identity

The PostgreSQL bootstrap reserves `nethub_issuer` as NOLOGIN, NOINHERIT,
NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION and NOBYPASSRLS. It has public
schema usage, no table/credential-function access and no role memberships in
either direction. Existing unexpected flags, memberships or direct public-schema
table/column/sequence privileges stop bootstrap for
operator review; they are not silently repaired. Bootstrap remains idempotent.

This role is for the privileged host's one-shot issuer boundary, following the
existing host maintenance model. No database password or login endpoint is
created, and the setup manifest remains version 3 with the same 22 files. The
web, authz and migration logins cannot assume the role. `OpenRole` deliberately
does not accept it as a password-backed client. Future issuer operations may be
granted explicit, narrow functions rather than broad device/table access.

A trusted host operation can select the SQL identity over PostgreSQL's local
socket before invoking fixed queries. This does not confine a compromised host:
host root/Docker and the authenticated PostgreSQL superuser remain trusted and
can reset session authorization or change privileges. Never accept arbitrary SQL,
publish that socket, or expose the host adapter as an HTTP execution endpoint.
The ordinary application logins cannot perform that identity transition.

Fresh initialization creates the reserved role. Existing PostgreSQL volumes do
not rerun bootstrap on image replacement. An existing deployment needs an
explicit reviewed bootstrap/upgrade operation before enabling an issuer; this
change does not run it, rewrite manifests, regenerate authority, start a worker,
grant issuance functions or contact a CA. Current device admission/lifecycle
does not require the issuer role and remains independent of that future upgrade.

The genuine PostgreSQL suite checks flags, memberships, schema/data/function
grants, application/migration refusal, selected host identity and actual denied
queries under that identity. It then reruns the real bootstrap hook, preserving
the existing idempotency check. The deployment hook and embedded setup template
are checked for identical content.
