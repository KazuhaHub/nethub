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

PR #43 merged as fea5cdc after all six checks passed on 1af30c3 (run
39213468715). Genuine PostgreSQL tests passed schema/identity matching,
concurrent single-use admission, signing/audit rollback and all three post-lock
disable/expiry cases. Ordinary local Go tests skip these native database groups. HTTP routes, runtime
key loading, authz listeners and the appliance UI were not implemented by that
service/storage change. The follow-up adds the enrollment HTTP handler with
host/origin, media/body and trusted-proxy boundaries, fixed diagnostics and 429
retry advice. PR #45 merged as 8bffd8b after six checks passed on 67a8adc (run 39215217352).
Its genuine PostgreSQL harness validated raw TCP HTTP output against the shared
schema and committed identity, with HTTP replay/version checks. Production
deployment exposure still needs implementation. The next runtime change adds
file-based claim/frp credential loading, an authz-role database connection,
bounded readiness and a private enrollment listener with graceful shutdown.
PR #46 merged as 0cab3df after all six checks passed on 910efc2 (run
39216642231). Genuine tests launched the compiled CLI and verified enrollment/key
loading, credential-free output and SIGTERM exit. Production frps/authz wiring, trust-generation reload and
appliance enrollment remain incomplete. See [the service boundary and recovery limits](../server/internal/device/README.md).

## W4-4: internal relay authorization

The callback handler checks the deployment signature, metadata device ID and
current tenant/subdomain/issuance timestamp under a device row lock. Revoked or
missing assignments deny. The agent renders `nethub-<device_id>-web` names and
the callback verifies them, fixing the old multi-device proxy-name collision.
HTTPS-only routing rejects custom domains and shared
proxy groups. The private listener requires exact socket peers, ignores forwarding
headers for authority, and bounds reads, concurrency and database work. The public
enrollment listener cannot serve callbacks; both listeners stop together.

Local Go tests/vet pass. The genuine PostgreSQL follow-up covers wrong/stale
signed assignments, revocation and claim replacement during observed row locks,
and the compiled runtime's actual callback requests, lock timeout, recovery and
listener separation. PR #47 merged as 48e2fa6 after all six checks passed on 3c24e5e (run
39219581415). Genuine callback, lock-race and compiled-process cases passed.
Real frps registration/tunnel traffic remains deployment acceptance. See [the boundary and sources](../server/internal/relayhook/README.md).

## W4-5: read-only relay observations

The observer reads the authenticated private admin API immediately and every 15
seconds. It never follows redirects or uses environment proxies; DNS results
must all remain private/loopback. Responses have bounded bytes, entries and
processing time. Recognized names/configurations must agree with the device route
policy before any storage call. Offline, missing and malformed responses cannot
refresh devices.

The authz store selects existing tenant scopes from the database, retains forced
RLS and updates only matching nonrevoked devices' last_seen_at with the database
clock. Busy device rows are skipped; empty observations do not extend online
state. The existing console's 45-second window expires old observations. Admin
failures emit fixed transitions and do not stop authorization listeners.

Local Go tests/vet pass. New genuine PostgreSQL cases check tenant/route/revocation
matching, unchanged identity fields, owner-scoped console online/expiry results,
lock skipping and denied web-role writes. The compiled CLI test polls a local
HTTP admin fixture at the actual 15-second cadence and checks persistence and
shutdown. All six checks passed on 0f06612388e9d610de7f056217a799324510ebfd
(run 39224267267); PR #48 merged as 59cb1c6. The compiled process observed the
real 15-second interval in 15.03 seconds, and genuine PostgreSQL cases passed.
Real frps response interoperability
and multi-client traffic still need W4 deployment acceptance. See [the observer
boundary and source references](../server/internal/relaystate/README.md).

## Remaining W4 work

- Complete device status,
  rotation and unenrollment handlers as the corresponding W4/W7 tasks require.
- W4-6: production frps/authz Compose wiring, real relay observation and source-IP
  verification in the actual container topology.
- W4-7/W4-8: verified HTTPS enrollment, PHP model save/configuration lock, private
  request-file handling, local idempotence, status and unenrollment.
- W4-9: the complete console-to-appliance workflow and every PLAN W4 acceptance
  check, with native/public evidence and credential-absence checks.

## W4-6 foundation in progress

A checksummed upstream frps 0.71.1 build uses the pinned Go 1.26.9 compiler and
patched network/crypto dependencies. It retains symbols and omits dashboard
assets with the upstream noweb tag. Source analysis found no affected imported
packages or reachable symbols; the unused OpenPGP module advisory is reported
separately. CI now builds/scans the assembled image and tests real nonroot startup,
admin authentication and the empty HTTPS-route response. These native image checks
still need to pass before merge. The generated production stack is unchanged.

The relaycert package creates a constrained deployment authority and renews a
matching leaf with a fresh key. Local tests include an actual verified TLS
handshake, renewal near authority expiry and invalid identity/key/PEM/time inputs.
It does not write files, schedule renewal, apply certificates or implement router
GUI issuance. Those lifecycle requirements remain open.

## W4-6 deployment bundle in progress

The generated bundle now separates immutable version-3 authority/configuration
backup from mutable relay leaf/trust files. Backup covers CA signing material
and the initial leaf snapshot; current leaves are validated against that authority
without forcing backup hashes to change on every renewal. Legacy bundles fail
explicitly and are preserved. No silent authority generation or in-place data
migration is implemented.

Compose adds nonroot authz and host-network frps. The latter binds its admin API
only to the private edge gateway; authz callbacks bind the explicit private
container address and accept only that gateway peer. Web/authz trust only Caddy's
forwarded-client address. Caddy sends device API requests to authz and denies
public health/hook paths. Issuer state has no application-runtime mount.

Local setup/CLI tests pass, including runtime leaf rotation preserving backup and
rejection of mixed leaf/key generations or changed unbacked trust. Native CI adds
official-checksum frps verification of the generated configuration, HTTPS device
enrollment, two actual frpc clients, tampered-claim rejection, verified TLS
passthrough and real frps observations reaching the console. All six checks passed
on 94f998794bad9174d3b098ccb53588d5bee081d4 (run 39230578213), and the native
deployment log confirms every new relay case and credential absence. The follow-up
retains the exact tested images for bounded native acceptance and uses the reviewed
Caddy template with only its test CA/hostname changed; current-head CI must pass
again before merge. Native public source-address acceptance is recorded below;
the external-proxy path, durable certificate automation and appliance/GUI lifecycle remain open.

PR #51 merged as d3ce2899e75a0b4f1f80859e8fb35dae67b70002 after all six checks
passed on 19c29f07bcea97c74180980e72c30ee99a974451 (run 39231661494). The final
native log reconfirmed official frps verification, both real clients and relay
observations, credential absence, browser regressions and all four image scans.

The same tested image archive was transferred to the Linux LXC and its checksum,
configuration digests, ordered rootfs diff IDs and platform were verified. Fresh
version-3 initialization/DNS/backup acknowledgement and scoped file doctor passed.
PostgreSQL, web and authz are running privately; web/authz are healthy, nonroot,
read-only, have only their intended mounts and publish no host ports. The original
public services were preserved during preparation. The subsequent bounded public
acceptance is recorded below.

Native loading exposed classic-versus-containerd image ID semantics. All four
configuration bytes and ordered layers matched the tested archive; containerd's
manifest descriptors referenced those exact configuration digests. The follow-up
image-content manifest records portable configuration/layer/platform identity
alongside the engine-specific ID. Raw evidence and all generated authority,
administrator and backup material remain outside Git.

D22 now requires automatic renewal, distribution and configuration based on the
PSP review, with reverse-proxy-owned console TLS. The owner selected option 2,
including router GUI certificate issuance, automatic installation and renewal in
v1; the earlier v1.1 scope record was incorrect (corrected 2026-10-19). See [the automation design](certificate-automation.md). Execution,
expiry and backup details still need implementation/validation; the earlier
private manual-renewal proposal is superseded. The installed configd source review
is retained outside Git. configd logs script stderr, so agent errors must never
dump credentials or raw enrollment responses; its output cache must be disabled
for the credential-bearing action. Full dispatcher logging/temp-file/crash paths
still require verification. Preserve the current SSH policy and recovery path.

## Native public acceptance

PR #52 merged as c6ec379 after six checks on d032355c43917a4a5e3b335a1d00fc9c381b9b25
(run 39234383994). The exact PR #51 images passed public console CA/hostname
verification and nine browser groups with zero CSP violations, browser errors or
unexpected external requests. Four screenshots were inspected. Three fresh
external IPv4 TLS connections through host-network frps matched both independent
HTTP source requests and established kernel TCP peers. The fixture backend's TLS
certificate and hostname were verified on each connection.

Two earlier collector failures were corrected and retained as failed evidence;
no product hook authorization was weakened. Each bounded window independently
restored original services and closed the test control listener before cancelling
its restoration timer. Authority, backup and private database were preserved. See
[the evidence and limits](../deploy/validation-w4.md). This does not complete the
external-proxy path, certificate automation or native appliance enrollment/GUI
acceptance.

## External proxy and device-owned CSR boundary

PR #54 merged as cd863d9 after six checks on
55daa202665e0c67ff6bc14aeb6153d2140fe8aa (run 39239990731). External mode omits
bundled Caddy, binds both HTTP origins to host loopback and trusts exactly the
edge gateway. An independent host TLS proxy passed login, secure cookies, device
enrollment, source-spoof rejection and non-loopback isolation in genuine Compose.
A supplementary native LXC run passed these flows without stopping existing
public services; all owned resources were removed. See [the scope and failed
fixture attempt](../deploy/validation-w4.md).

PR #55 merged as da3fa29 after six checks on
cf9224cdd4d7b5479045183d63281e47c66b73e9 (run 39240210910), including the CSR
package under Linux race testing. Router GUI keys will remain device-generated;
the server validates the signed P-256 CSR against the exact current assigned
name. Authorization, ACME, delivery, native installation and renewal remain open.

The local relay maintenance work assesses actual validity dates, avoids a fixed
lead exceeding a short certificate's lifetime, distinguishes authority expiry
and non-extendable leaves, and verifies the actual served TLS fingerprint. Local
tests/vet pass. Draft PR #56 now adds a durable OS lease/journal, complete private
generations, bounded same-generation retries, verified apply/rollback, a Linux
root host adapter and systemd service/timer samples. It rejects aliased/hardlinked
authority backups and checks the exact existing frps mounts/identity before
recreation. The new genuine Compose scenario exercises a real due leaf, failed
recreation/verified rollback, persisted-generation reuse, two connected official
clients, a scheduled host invocation and unchanged-content suppression. Current
head CI and native evidence remain pending. CA rotation/trust ACK, expired-job
replacement and the router GUI lifecycle remain required; W4-6 is not complete.

The first complete maintenance deployment run (39245558996, head
0d587593611b892ad5730ea0971b3ca263221c1a) passed real due-leaf renewal, an
injected recreation failure with verified rollback, persisted-generation reuse,
fresh served-fingerprint checks, two official frpc clients, an actual host timer
and unit-template verification. The measured retry-to-both-tunnels interval was
698 ms in that isolated run. All four image scans and existing bundled/external
proxy/browser/migration regressions passed. Its control-plane job stopped at
module tidy because x/sys needed promotion from indirect to direct; no merge is
authorized from that run. The corrected dependency metadata and extra runtime
container/source-independence checks require another exact-head CI run. Native
public maintenance acceptance and the remaining certificate scope stay open.

## Same-root maintenance acceptance and GUI chain follow-up

PR #56 merged as 689e8e9 after six checks on d099ee803df258c5948b57aef0848169578ff473
(run 39248588114). Genuine deployment logs confirm verified rollback, persisted
generation reuse, two real clients, actual timer execution and 690 ms recovery
in the isolated CI test. Native public acceptance passed with that exact CI host
binary and earlier PR #51 application images: external verified control TLS saw
the new leaf and both fixture routes recovered. Trigger-to-confirmation measured
4.0 seconds with 17 failed and 62 successful fresh control/HTTP probes after the
trigger. Original listeners were restored and 7000 closed before the independent
timer was cancelled; the valid renewed generation and original CA were retained.
See the detailed evidence and limits in deploy/validation-w4.md.

The GUI follow-up validates returned chains against signed device CSRs and
independent roots. Local tests/vet pass; current-head CI is still required.
The proposed ACME flow now prefers central HTTP-01 where the relay can serve
port 80, with optional DNS-01 fallback. NAT does not require DNS-01 when the relay
can answer validation for the assigned name. No challenge publisher, ACME job,
authenticated key binding or appliance installer is implemented by this change.
Trust/ACK, CA rotation, expired-candidate replacement and W4-7/8/9 remain open.
