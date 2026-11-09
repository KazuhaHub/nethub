# Isolated host issuer identity

This records the initial role boundary. The current issuer also has the narrow
job, progress and completion functions added by later migrations; see the
[queue contract](../guiissuer/README.md) and [protected worker](../guiissuer/HOST.md).
The original no-login, no-membership and no-raw-table boundary remains.

The PostgreSQL bootstrap reserves `nethub_issuer` as NOLOGIN, NOINHERIT,
NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION and NOBYPASSRLS. It has public
schema usage, no table/credential-function access and no role memberships in
either direction. Existing unexpected flags, memberships, permission to create
objects in public, credential-function execution, or direct table/column/sequence
privileges stop bootstrap for operator review; they are not silently repaired.
Missing credential functions during fresh initialization are allowed; the guard
also checks existing deployments after migrations. Bootstrap remains idempotent.

This role is for the privileged host's one-shot issuer boundary, following the
existing host maintenance model. No database password or login endpoint is
created, and the setup manifest remains version 3 with the same 22 files. The
web, authz and migration logins cannot assume the role. `OpenRole` deliberately
does not accept it as a password-backed client. Issuer operations use explicit,
narrow function grants rather than broad device/table access.

A trusted host operation can select the SQL identity over PostgreSQL's local
socket before invoking fixed queries. This does not confine a compromised host:
host root/Docker and the authenticated PostgreSQL superuser remain trusted and
can reset session authorization or change privileges. Never accept arbitrary SQL,
publish that socket, or expose the host adapter as an HTTP execution endpoint.
The ordinary application logins cannot perform that identity transition.

Fresh initialization creates the reserved role. Existing PostgreSQL volumes do
not rerun bootstrap on image replacement. An existing deployment needs an
explicit reviewed bootstrap/upgrade operation before enabling an issuer; this
initial role bootstrap does not rewrite manifests, regenerate authority, start
a worker or contact a CA. Later migrations grant issuance functions only when
the reserved role exists; an older volume still needs an explicit reviewed
role/function upgrade before enabling issuance. Device enrollment and ordinary
lifecycle operations remain independent of that issuer upgrade.

The genuine PostgreSQL suite checks flags, memberships, schema/data/function
grants, application/migration refusal, selected host identity and actual denied
queries under that identity. It then reruns the real bootstrap hook, preserving
the existing idempotency check. The deployment hook and embedded setup template
are checked for identical content.
