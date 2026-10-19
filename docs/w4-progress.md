# W4 progress

W3 closed with PR #39, merge 45b79ac, after all six checks passed on final head
c41614b (run 39206137367). Kazuha accepted the fresh Debian VM/public-ingress
environment on 2026-10-18. Enrollment remains under implementation.

## W4-1: protocol foundation

Merged in PR #40 as e26f6af. All six checks passed on 41ff3c5 (run 39207923123).
The genuine PostgreSQL log confirms platform_forward_migration and
bounded_platform_identifiers passed; the new schema is tested on an existing
OPNsense record as well as the current role/RLS fixture.

The first protocol version is 1.0.0. Ten shared draft-2020-12 schemas cover
enrollment, strict domain claims, status, rotation and unenrollment. Twenty-three
valid/invalid examples are consumed by both language suites. Ordinary messages
permit bounded optional extensions; claims retain exactly five fields.

Go defines the wire types and a bounded enrollment parser. It rejects duplicate
keys, invalid UTF-8, missing/null required fields, excessive bodies/nesting/arrays,
malformed versions and incompatible majors. It extracts exact known field names
before decoding; case-insensitive struct decoding cannot turn an unknown field
into a settings override. Errors return fixed diagnostics and no credential-bearing
request. The OPNsense request builder uses only Python's standard library;
jsonschema is a development/CI dependency.

Migration 00003 replaces the original OPNsense-only constraint with the same
bounded ASCII identifier rule used by the schemas. It preserves grants/RLS and
does not modify old migration files. Actual-role integration tests start from
migrations 00001/00002 with an existing OPNsense device, verify the old constraint,
apply the forward migration, and verify data preservation. Separate checks cover
future identifiers, invalid identifiers and denied web-role platform updates.
An accepted identifier does not establish support for another platform's agent.

Local Go contract tests and 36 Python contract tests passed. Removing the token
from a shared valid fixture made both real suites fail on that fixture; the file
was restored, and positive tests were rerun. These are contract and parser tests,
not HTTP endpoint, native appliance enrollment or full W4 acceptance evidence.
The PostgreSQL upgrade test is exercised by the existing genuine-database CI
harness; ordinary local Go tests skip that integration group without its flag.
Check the current PR's six exact-head jobs before merging.

## W4-2: signed domain claims

Merged in PR #42 as ca40ddb after all six final-head checks passed on 5eb474e
(run 39210455674), including the claim package under go test -race and the genuine
PostgreSQL/deployment harnesses.

The claim package signs canonical five-field JSON using HMAC-SHA256 over its
unpadded base64url representation. Verification rejects noncanonical JSON/base64,
duplicate/unknown fields and invalid timestamps even when correctly signed. Key
selection is explicit and retained verification keys support rotation. Errors
return no input or partial identity. An independent Python known-answer vector,
field/signature tampering, malformed signed payloads, defensive key copies and
concurrent use are covered by local tests. A five-second fuzz run completed
57,796 executions without failure; this is bounded fuzz evidence, not a proof of
complete security coverage. The final-head CI results above include race and
integration checks.

NextIssuedAt advances at PostgreSQL microsecond precision across same-second
rotations and clock rollback. The future handler must hold the device row lock
and persist that exact value; this helper does not establish database ownership,
revocation or transaction correctness. Runtime key loading and relay-hook wiring
remain W4-3/W4-4 work. Certificate automation decisions merged separately in
PR #41 as da9f84b after six checks passed (run 39209680883).

## W4-3: atomic enrollment admission and storage

The device service validates versions before token consumption, prepares hashed
credentials, validates public relay trust and bounds per-IP attempts/Argon2 work.
EnrollmentStore derives tenant/owner from the one-use token and commits device
creation, signing and audit together. Migration 00004 locks creator then token
and checks eligibility with the clock after both waits; authz still cannot read
users directly. Subdomain conflicts use bounded savepoint retries. Boolean
cluster_hint becomes nullable display text, never an authorization input.

Local service/parser/store unit checks pass. Ordinary Go tests skip native
database groups; inspect the current enrollment PR's genuine PostgreSQL CI before
claiming its new rollback/race/schema-output cases passed. HTTP routes, runtime
key loading, authz listeners and the appliance UI are not implemented by this
service/storage change. See [the service boundary and recovery limits](../server/internal/device/README.md).

## Remaining W4 work

- W4-3/W4-4: device handlers and bounded internal frp hooks with transactional
  token consumption, device authorization and safe error handling.
- W4-5/W4-6: relay observation, production frps/authz Compose wiring and source-IP
  verification in the actual container topology.
- W4-7/W4-8: verified HTTPS enrollment, PHP model save/configuration lock, private
  request-file handling, local idempotence, status and unenrollment.
- W4-9: the complete console-to-appliance workflow and every PLAN W4 acceptance
  check, with native/public evidence and credential-absence checks.

D22 now requires automatic renewal, distribution and configuration based on the
PSP review, with reverse-proxy-owned console TLS and router GUI certificates
remaining v1.1. See [the automation design](certificate-automation.md). Execution,
expiry and backup details still need implementation/validation; the earlier
private manual-renewal proposal is superseded. The installed configd source review
is retained outside Git. configd logs script stderr, so agent errors must never
dump credentials or raw enrollment responses; its output cache must be disabled
for the credential-bearing action. Full dispatcher logging/temp-file/crash paths
still require verification. Preserve the current SSH policy and recovery path.
