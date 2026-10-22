# Device enrollment service

Protocol 1.1 optionally admits a canonical P-256 GUI public key in the same
transaction that consumes the one-use token and creates the assigned identity.
The response acknowledges its SHA256 DER fingerprint. Migration 00006 prevents
changing or clearing that binding, including backfilling a legacy null value;
readiness also requires the guard to be enabled. The web role has no column grant.
Legacy requests remain unbound and can re-enroll when certificate support is
enabled. There is no bearer-only key-binding endpoint. Later issuance must also
authorize the live assignment and require a signed CSR with this exact key.

The native request helpers understand the optional key and require its matching
acknowledgement when supplied. Native key generation, certificate job admission,
issuance/delivery and installation are not enabled by this admission change.

This is the admission/transaction layer, HTTP adapter and enrollment runtime for
W4-3. `nethub authz` serves the handler on a private listener. Internal relay
callbacks have a separate listener. Production Compose exposure and native
OPNsense enrollment have passed public acceptance; see the plugin W4 report.

Runtime startup reads the deployment's lowercase 64-character hex claim key and
frp token from private regular files, decoding the claim key into 32 raw bytes.
Unix group/world-readable secrets and symlink files are refused. Relay CA input
is public PEM and is bounded separately. No secret value is accepted through a
command argument. Start after applying migrations and provide only the authz-role
database password, never owner credentials. Keep this HTTP listener behind the
verified HTTPS reverse proxy with explicitly configured trusted proxy CIDRs.

`GET /healthz` (also HEAD) checks the authz database role/function access and the
current published public trust validity with a two-second context bound. It does not
prove that a relay is reachable or that the served relay leaf is current. The
runtime bounds headers/read/write/idle times and drains requests on SIGTERM.
Claim keys and the frp token remain startup snapshots. With the production
repository, startup and readiness prefer the independently validated current
database publication, including when the mounted bootstrap CA has expired.
Bootstrap trust is allowed only for an uninitialized head and must be currently
valid. Once publication is observed, missing, unavailable, wrong-name or expired
trust cannot fall back to the bootstrap. No TLS verification is disabled.

Enrollment preflight is bounded by the existing source-IP and worker limits.
It does not determine the returned bundle: registration still selects current
trust under the head lock before token consumption and supplies that exact
snapshot to the signing callback. An initialized callback refuses an empty
snapshot; post-commit fetching cannot repair or replace it. These are public
trust/startup rules, not evidence that frps or a native device applied a generation.

`NewHTTP` serves `POST /api/v1/devices/{enroll,status,unenroll}`. It checks the configured host,
optional exact Origin, JSON media/encoding, canonical path and a 64 KiB body
limit before admission. Query parameters are rejected; cookies do not establish
device authority. Client addresses come from the socket or an explicitly trusted
forwarding chain. Untrusted forwarding headers cannot change the rate-limit key.
Responses prohibit caching and expose fixed errors without logging request or
dependency values. Successful creation returns 201; invalid/replayed credentials
return the same 401, capacity limits return 429 with Retry-After, and internal
failures return 503 without a partial credential response.

Status and removal authenticate the device bearer secret and recheck its hash
under the mutation lock. See [lifecycle boundaries](README-lifecycle.md). Rotation
is not exposed by this increment.

The service validates the shared request and protocol major before hashing or
calling storage. It validates a bounded relay configuration/public root bundle,
canonicalizes PEM, and checks validity again before signing after database waits.
This does not prove that a live relay is reachable or currently presents the
expected leaf; deployment/automation must verify that separately.

Admission has ten attempts per source IP per minute, at most 10,000 live IP
entries, and two concurrent Argon2 workers. IPv4-mapped addresses share the IPv4
budget. Live entries are not evicted to admit new attacker-chosen keys. Operations
have a ten-second context bound; failures expose fixed diagnostics.

The one-use token is decoded and hashed as 32 raw bytes, matching console token
issuance. A separate random device secret is Argon2id-hashed. Storage receives
only their digest/hash, bounded metadata, server-generated subdomain candidates
and the resolved source IP. Candidates use unbiased random letters/digits,
exclude reserved names and have bounded collision retries.

The repository derives tenant and owner exclusively from the token. It holds
user/token locks, rechecks post-wait eligibility, inserts through transaction-local
RLS, signs the assigned identity and appends audit before commit. The plaintext
secret/claim/relay material is returned only after successful commit. Unknown,
expired, future, disabled-owner and replayed tokens share the same denial.

The agent's boolean cluster_hint becomes nullable display text in PostgreSQL
(`cluster member` or null). It is never an authorization input and does not
introduce platform-specific fields into the wire protocol.

Signing, audit or exhausted allocation failures before commit roll back all
changes. A lost commit acknowledgement or lost HTTP response can leave the whole
transaction committed while the caller lacks its result. Do not transparently
reuse a consumed token or persist plaintext credentials to make replay succeed.
The later UI must explain recovery: inspect/revoke the unclaimed device and
issue a fresh token. A local PHP save failure also needs explicit recovery.

Local tests cover admission, secret separation, configuration failures, capacity,
bounded entropy and trust expiry during registration. The genuine PostgreSQL
harness additionally checks service output against the shared schema, exact
database/claim identity, one-winner replay behavior, cross-tenant allocation
conflicts, signing/audit rollback, and eligibility changes during user/token locks.
The admission/storage tests passed in run 39213468715. The HTTP follow-up changes
the genuine harness to use a TCP HTTP server and validate its raw response against
the shared schema, then compare it with committed identity and audit state. Its
HTTP/database cases passed in run 39215217352; ordinary local Go runs skip them.
The runtime follow-up additionally launches the compiled CLI in the isolated
PostgreSQL container, checks readiness, enrolls through that process, verifies
the loaded signing key, checks output for credentials and requests graceful
termination. These runtime cases passed in run 39216642231. The callback
follow-up adds native dual-listener and locked-row tests; those results remain
pending its own CI.
