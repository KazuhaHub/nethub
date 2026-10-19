# Device enrollment service

This is the admission/transaction layer for W4-3. HTTP routes, the authz runtime,
frp hooks and appliance enrollment UI remain unfinished. It is not a reachable
device API yet.

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
Check the current PR's CI logs before claiming those native checks passed.
