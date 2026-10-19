# Device enrollment service

This is the admission/transaction layer, HTTP adapter and enrollment runtime for
W4-3. `nethub authz` can serve the handler on a private listener. Relay hooks,
production Compose exposure and appliance enrollment UI remain unfinished.

Runtime startup reads the deployment's lowercase 64-character hex claim key and
frp token from private regular files, decoding the claim key into 32 raw bytes.
Unix group/world-readable secrets and symlink files are refused. Relay CA input
is public PEM and is bounded separately. No secret value is accepted through a
command argument. Start after applying migrations and provide only the authz-role
database password, never owner credentials. Keep this HTTP listener behind the
verified HTTPS reverse proxy with explicitly configured trusted proxy CIDRs.

`GET /healthz` (also HEAD) checks the authz database role/function access and the
configured public trust validity with a two-second context bound. It does not
prove that a relay is reachable or that the served relay leaf is current. The
runtime bounds headers/read/write/idle times and drains requests on SIGTERM.
Trust and keys are startup snapshots; automatic generation reload is still
certificate-maintenance work.

`NewHTTP` serves only `POST /api/v1/devices/enroll`. It checks the configured host,
optional exact Origin, JSON media/encoding, canonical path and a 64 KiB body
limit before admission. Query parameters are rejected; cookies do not establish
device authority. Client addresses come from the socket or an explicitly trusted
forwarding chain. Untrusted forwarding headers cannot change the rate-limit key.
Responses prohibit caching and expose fixed errors without logging request or
dependency values. Successful creation returns 201; invalid/replayed credentials
return the same 401, capacity limits return 429 with Retry-After, and internal
failures return 503 without a partial credential response.

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
termination. Its native result is pending runtime CI.
