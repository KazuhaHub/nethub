# W3 decision brief

Status: proposals only. W3 implementation has not started. PLAN requires owner
confirmation of D8, D11, and D15 before W3, plus the relevant D16/D18 choices.
Kazuha requested uninterrupted rest; no question is pending in the UI.

The accepted W0 scope and W2 validation remain unchanged. This brief collects the
remaining decisions so the next review can cover them together.

## D8: v1 scope

Propose the scope already described in DESIGN sections 1 and 6:

- OPNsense-only enrollment with a single-use, 15-minute token and a random
  device subdomain; signed device claims and opaque device secrets.
- TLS passthrough GUI access, online/offline state, explicit source-IP Open
  grants, revocation, device-side kill switch, and credential rotation.
- One tenant per installation; admin/member roles, invitation-only accounts,
  local password login, multiple OIDC providers, and audit history.
- Self-hosted Compose deployment, init/doctor, backup/restore, and staged plugin
  release support. SAML remains v1.1; router configuration management remains
  outside v1. Console authentication does not replace the device's own login.

Already confirmed: source-IP grants last 30 minutes and renew only on explicit
Open; heartbeat-based revocation uses 10s/30s and rejects Ping/Login/NewProxy;
keep browser port 8443 and both device hostname security checks enabled.

## D11: database and process permissions

Propose the process split and table model in DESIGN section 6, with these concrete
boundaries and additions. These are proposed grants, not implemented migrations.

| Role | Authority |
|---|---|
| nethub_owner | Migration-only login, owns schema/functions, BYPASSRLS where needed by tenant-unknown token consumption. No runtime service receives its password. |
| nethub_web | Console accounts/sessions/invites/OIDC; display columns on devices; label and one-way revocation; limited token issuance; append-only audit; narrow Open/cutoff request writes. No device insertion or identity-column writes. |
| nethub_authz | Device identity, enrollment, claims, tunnel admission, state, grant reads, and cutoff processing. No console users/sessions/invites/OIDC authority. |
| nethub_backup | Read-only pg_dump with BYPASSRLS. Dedicated backup credential, no writes. |

All runtime roles are non-superuser and cannot create roles/databases. Web/authz
have no BYPASSRLS or ownership. Tenant tables use ENABLE and FORCE RLS; each store
transaction sets app.tenant_id locally. Member ownership is additionally enforced
in shared store functions, since tenant RLS alone does not isolate members.
The only privileged enrollment consumer fixes search_path, revokes PUBLIC execute,
returns the tenant and creator, atomically consumes once, and enforces expiry.

Keep the proposed core tables: tenants, users, user_identities, oidc_providers,
invites, sessions, devices, enroll_tokens, audit_log. No per-device frp_token_hash:
the shared relay token is a deployment secret, not a device identity.

Additional proposals needed before migration:

- One-way device revocation: database enforcement rejects true-to-false changes.
  A revoked identity is replaced by new enrollment. Web cannot change ownership,
  tenant, subdomain, claim timestamps, device-secret hashes, or cluster metadata.
- Open grants: device_access_grants records tenant, device, user, exact source IP,
  granted_at, and expires_at. A narrow function validates actor/device ownership
  and assigns the fixed 30-minute expiry; only explicit Open can renew. Authz
  reads unexpired matching grants. No address ranges or traffic-based extension.
- Immediate cutoff: device_disconnect_requests records tenant, device, actor,
  requested_at, and processing state. Web may request but cannot acknowledge or
  clear it. Authz processes it through the accepted heartbeat admission mechanism.
  A request must not promise that every established browser stream stops at once.
  Product wording and the completion condition must reflect W0's observed limits.
- Web gets only the enroll-token columns needed for issuance/status, with database
  timestamps/default lifetime; token plaintext is returned once and never stored.
- Audit append is serialized by a narrow function, with no UPDATE/DELETE for
  runtime roles. Its hash chain is an operational integrity check, not protection
  against a compromised database or signing authority.
- Invites expire after 72 hours and are single-use; propose optional provider_id
  binding in v1. OIDC claim requires the original invitation flow, verified email
  match, and an enabled provider. Existing identities bind by issuer/subject.
- Keep at least one enabled local-password admin. Serialize changes that might
  remove the last such account, including concurrent disable/demotion requests.

Bootstrap secret exception: PostgreSQL initialization needs all four role
passwords as well as the bootstrap superuser password. Propose allowing that
explicit exception for the database container; PostgreSQL already controls those
roles. Web/authz/migrate/backup still receive only their own credentials. The
CA private key and claim signing key do not belong in the database container.
Do not put passwords in process arguments, SQL text logs, image layers, or a
shared application .env. The illustrative psql -v password command in PLAN must
be replaced with an input/file-based mechanism before implementation.

Compromise limits remain honest: web compromise can take over the console,
issue enrollment tokens, request grants/cutoffs, revoke devices, and redirect its
own UI. It cannot obtain a valid signed claim for an existing subdomain. Authz,
frps, and Caddy remain stronger trust points as described in the threat model.

## D15: initial administrator

Propose init before the database: generate service-separated secrets/configuration,
show a mandatory backup acknowledgement, and print the subsequent commands.
Compose starts PostgreSQL, runs migration once, then starts web. A local
`nethub admin create --email ...` command creates the first admin after migration;
read the password from an interactive prompt or protected input, never an argv
value. Specify a separate one-shot admin bootstrap service rather than granting
schema-owner credentials to web. Subsequent account management uses the console.

## D16: W3 implementation choices

Propose the existing PLAN choices: Go 1.26.x, standard net/http, flag, log/slog,
pgx/v5 pools, goose/v3 embedded SQL, React/TypeScript/Vite, and the already accepted
shadcn/native-dialog integration. Pin exact versions and image digests after
checking official sources at implementation time; this brief does not pin them.
Use a nonroot distroless static runtime for the CGO-disabled binary. The development
PostgreSQL endpoint binds only to workstation loopback. Production has no published
PostgreSQL port. Argon2id and OIDC details follow the existing design, with security
parameters verified when implemented. Protocol version rules remain a W4 decision.

## D18: domain layout

Propose a separate console hostname, such as console.example.com, and a device
wildcard under router.example.com. Console host-only cookies use the __Host-
prefix. Reserve any console label if an owner instead chooses a hostname below
the device wildcard. Actual deployment names remain outside repository records.

## Acceptance work after the decisions

1. Pin the approved toolchain/dependencies and create the module/front-end shell.
2. Test fresh and repeated database initialization and migrations, including secret
   handling, actual role grants, forced RLS, and two-tenant negative cases.
3. Exercise member/admin ownership, forbidden device identity mutations, token
   one-time consumption under concurrency, one-way revocation, and last-admin races.
4. Test password/session/CSRF/rate-limit/proxy-IP boundaries and strict CSP in the
   actual browser, including the selected native dialog flows.
5. Verify clean Compose startup, failure when migration fails, service-specific
   secret mounts, initial administrator creation, backup acknowledgement, and
   actionable init/doctor errors. Never represent placeholders as working features.

W4 still needs D19 enrollment address discovery, D22 CA enrollment/rotation details,
and protocol version decisions. Formal signing/publication remains D13; the private
repository protection-plan limitation and public disclosure decisions remain W7 work.

## Development readiness observed on 2026-10-18

W2 merged as `43f9307`; packaging boot repair merged as `fcaf6fe`. The isolated
server already has a working Docker daemon (29.2.1) and Compose (5.1.0), four
logical CPUs, 4 GiB RAM, and about 8 GiB free disk at observation time. Existing
services were left running; no database or product stack was started. These are
readiness observations, not a successful Compose deployment.

The workstation has Node 24.14.0 and Go 1.27.0. PLAN calls for Go 1.26.x; the
existing CI selects 1.26.0. A separate 1.26.0 toolchain is being prepared without
changing the global installation. Select a supported patch version before W3
implementation and keep local/CI/container builds aligned.
