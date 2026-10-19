# Durable router certificate requests

`GUIRequestStore` retains one original signed CSR per enrolled device. It derives
the assigned host from the locked device's subdomain and a trusted deployment
domain, verifies the enrollment-bound public key and exact CSR signature/SAN,
then inserts the request and one audit event in the same transaction. A retry of
the same DER returns the same request ID. A newly signed CSR, including another
ECDSA signature over otherwise identical content, conflicts instead of creating
another issuance identity. Certificate generations and renewal jobs are separate
future records; the CSR is not consumed after one issuance.

The caller must authenticate the device secret first. Under the parent device's
row lock, the store rechecks that verified credential hash, tenant, revocation,
subdomain and immutable enrollment key. `Read` applies the same checks before
returning the exact original public CSR for protected local-cache recovery.
Credential rotation does not replace the CSR; an old verified credential cannot
read or submit after rotation. Changed domain assignments require explicit
re-enrollment/recovery, rather than silently replacing the retained CSR.

Migration 00007 forces tenant RLS, grants the authorization role only SELECT and
INSERT, and grants the web role no access. A trigger locks the parent device and
rejects stale/missing key bindings, revoked devices and mismatched host labels.
Updates/deletes fail even for the owner through normal SQL. The backup role's
existing read grant includes the new table. The owner remains a trusted migration
authority capable of DDL; triggers do not protect against a malicious owner.
`Health` requires the authorization role, both read/insert privileges, no mutation
privileges, forced RLS and the enabled binding guard before admission is exposed.

Raw CSR/key/host fields are excluded from ordinary JSON. The audit event contains
only the request ID and CSR fingerprint. No private key, CA account or network
operation enters the database transaction. PostgreSQL does not verify X.509
signatures: an issuer must independently revalidate the retained CSR, trusted
deployment domain, enrollment key and live assignment before each external
mutation and delivery. Direct access to authorization-role SQL is not an issuance
grant. No HTTP endpoint, worker, certificate delivery or native installation is
enabled by this boundary alone.

The genuine PostgreSQL suite covers eight concurrent identical admissions, one
record/audit, changed signed bytes, wrong key/name, exact readback, credential
rotation, legacy bindings, changed deployment domains, revocation and a blocked
admission that loses to revocation. It also checks actual web/authz/owner grants,
tenant RLS and disabled-guard readiness. Run `sh server/tests/postgres.sh` for the
isolated role/migration suite; ordinary Go tests skip this database acceptance.
