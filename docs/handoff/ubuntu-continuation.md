# Ubuntu continuation ledger

Date: 2026-11-15. This is a continuation record, not a replacement for the
[29-requirement snapshot](remaining-work.md), PLAN or DESIGN. A skipped external
action remains an open acceptance requirement. No release is accepted.

The owner requested sequential development and asked that work requiring owner
participation be recorded and skipped temporarily while independent work continues.

## Current work

- Complete clone and original handoff integrity verification passed.
- PRs 231 and 242 remain open and unmerged at their recorded handoff heads.
- [PR 243](https://github.com/KazuhaHub/nethub/pull/243), source
  `870eb575cec13f4869e7848aac2cdc9b7c93307a`, adds closed native package invariant
  diagnosis without changing any comparison, deadline or mutation replay rule.
  All six CI jobs in `43723295466` passed; its exact-source image gate was
  independently validated. Installed-native `43723295382` failed in dedicated
  heartbeat-client verified-TLS preparation, before native migration; its closed
  report confirms owned-image cleanup. Cold recovery `43723295368` passed within
  its isolated scope. The upgrade cause is still unknown; both the historical
  upgrade failure and this separate preparation failure remain failed.
- That source passed 141 focused tests; an Ubuntu 24.04/PHP 8.3/pinned-Node
  environment passed 1256 agent/plugin tests with 11 environment-dependent skips.
  Pinned console formatting, 26 tests and build, Go 1.26.11 race/vet/build and
  three-way frp 0.71.1 checks passed. Local actual PostgreSQL boundaries passed
  eight top-level cases; the separate revocation-load case was not enabled.
  Initial incomplete-environment attempts failed and were corrected by providing
  dependencies, not changing assertions.
- FreeBSD contracts `43723295424` passed 248 cases with all 256 source files
  verified against exact Git blobs. Appliance preparation `43723295477` passed;
  its original ZIP digest and all four screenshot hashes were verified, and its
  three distinct page views were reviewed. Neither is enrolled upgrade acceptance.
- [PR 244](https://github.com/KazuhaHub/nethub/pull/244), source
  `ed63c7b`, separately supplies the portable helper's missing Node/OpenSSL
  prerequisites. Runtime smoke checks and all six CI jobs passed. The full helper
  on the host still requires the documented host PHP prerequisite. Do not
  substitute this source's CI images for PR 243's native diagnosis.
- [PR 245](https://github.com/KazuhaHub/nethub/pull/245), source
  `38bec4dd17f7d63f330f958f163f5c61e43e8a64`, fixes a separately demonstrated
  install-guard/reconcile-lock race and adds closed observations for the earlier
  TLS preparation failure. Regression tests fail against the old hook; the fixed
  hook passed a complete ordinary-user Ubuntu container suite (1254 passed,
  18 environment/privilege skips). A real FreeBSD lock case is now required by
  the native receipt. All six CI jobs in `43727962907` passed. Installed-native
  `43727962910` passed WAN recovery, then failed a private input transfer before
  any migration baseline step. Cold recovery `43727962999` passed its isolated
  scope: baseline route recovery 89899 ms and initial issuance recovery 173116 ms
  from source stop, with cleanup confirmed. Preparation `43727963052` passed.
  FreeBSD `43727962948` failed two portable shim cases while its required
  actual lockf case passed; that failed receipt remains failed. Original upgrade
  attribution and actual new-hook installation acceptance remain pending; this
  source has no acceptance from the earlier source's images or results.
- [PR 246](https://github.com/KazuhaHub/nethub/pull/246), source
  `257828a70ec04a5298c87a32b033d2ff8c706043`, binds the temporary test shim to
  the selected Python interpreter. No production hook or assertion changes.
  Local focused tests passed (28, with one native skip); all six CI jobs in
  `43728881313` and native contracts `43728881308` passed. The latter passed 252
  cases with 257 exact Git blobs verified. It is not installed upgrade acceptance.
- [PR 248](https://github.com/KazuhaHub/nethub/pull/248), source
  `b2bfb5070832fcc7deae202e197c43f22bcfb77f`, retains the original short-circuit
  order so a known fingerprint mismatch is saved before a later GUI read could
  mask it. All six CI jobs in `43730193170`, FreeBSD `43730193179` and preparation
  `43730193161` passed. Installed-native `43730193174` passed WAN recovery, then
  failed the package probe environment boundary before a migration report or
  package switch. Cold recovery `43730193155` passed its isolated scope, with
  baseline route recovery 128348 ms and initial issuance recovery 172474 ms from
  source stop; cleanup passed. Both installed preflight failures remain failed.
- [PR 249](https://github.com/KazuhaHub/nethub/pull/249), source
  `52e3362625b1de18399bb7ff6a68aeaca516aabb`, separates the package boundary into
  fixed host/nonce/marker/interface/LAN/route/WAN checkpoints without changing
  any guard, operation or replay policy. Its 151 focused tests and all six CI
  jobs in `43760255115` passed. The exact-source tested-image gate was
  independently validated. Installed run `43760255139` failed after its WAN
  recovery substep at the separate console check (`tls` / `http_failure`),
  before any migration baseline or package switch. Owned-image cleanup passed.
  Cold recovery `43760255138` passed within isolated scope: baseline route
  recovery 129162 ms and original-request issuance recovery 161030 ms from
  source stop (175710 ms from checkpoint), with cleanup confirmed. This does not identify
  the historical upgrade cause or accept either earlier failed installed run.
  Preparation `43760255136` and FreeBSD `43760255102` subsequently passed; 252
  contract cases, all 257 Git blobs, the preparation archive and four screenshot
  hashes were verified. Three distinct preparation views were reviewed. Those
  preparation/contract checks do not establish enrolled upgrade acceptance.
- PR 249's later source `359bf94eab8c3339671fb1b0af1a6c4133f26ad1` corrects the
  console probe's TCP/TLS error-stage classification and retains a bounded
  read-only guest package snapshot plus credential-free host HTTPS observation
  on the existing post-WAN refusal path. The original failure is always raised,
  including when diagnostics succeed or fail. No original probe, enrollment,
  Open, package or SQL mutation is replayed. All original deadlines and guards
  remain unchanged. A controlled old/new comparison reproduced the diagnostic
  distinction with both outcomes still failed; 194 focused tests passed.
  Fresh source-specific CI `43766613173` and installed `43766613555` are pending;
  the earlier source's images and scoped results are not substituted.

  Source `359bf94` subsequently passed all six CI jobs in `43766613173`,
  FreeBSD `43766613099` (252 cases, 258 source blobs) and preparation
  `43766613091`. Installed `43766613555` failed before creating the guest,
  at authz log JSON decoding during heartbeat preparation. No package or
  post-WAN diagnostic was reached. Its failed outcome and owned-image cleanup
  remain retained in the [source-specific checkpoint](evidence/ubuntu-359bf94/index.json).
  Cold recovery `43766613544` passed isolated scope with cleanup confirmed;
  baseline recovery was 108825 ms and original-request issuance recovery was
  141275 ms from source stop. The producer's 13 required console image hashes
  were checked: six matched reviewed bytes and seven changed views were reviewed.
- [PR 250](https://github.com/KazuhaHub/nethub/pull/250), source
  `2523ab981f953e0a4d5dce994fbdff593d09d8fe`, addresses a separately reproduced
  Docker log framing defect. An unterminated final JSON fragment may receive
  at most one second to complete, with the same container and every original
  byte preserved. Complete invalid records, changed history and timeouts still
  fail; observation waits consume existing cutoff clocks. Ten log tests, three
  heartbeat tests and 214 related tests passed. Fresh source-specific CI and
  installed acceptance remain pending. This does not prove the prior native
  failure was caused by log framing.

  Source `2523ab9` subsequently passed six-job CI `43772146655` and its
  independently verified exact-source image gate, FreeBSD `43772146565`
  (252 cases, 258 source blobs) and preparation `43772146624`. Installed
  `43772146507` failed before guest creation with fixed plain-prefix,
  service-failure and invalid-record hints; owned-image cleanup passed.
  The reader refused a complete service-failure record, rather than accepting
  an incomplete tail. The old aggregate category does not identify which of
  its three known service-failure messages occurred. Cold `43772146549` passed
  isolated recovery and cleanup: baseline 126637 ms and original-request
  issuance 178305 ms from source stop. These distinct outcomes and all 13
  reviewed console images are retained in the
  [source-bound checkpoint](evidence/ubuntu-2523ab9/index.json).
- [PR 251](https://github.com/KazuhaHub/nethub/pull/251), source
  `d33302f5420f6d90cc04b7e5142bc9660569d987`, makes unexpected authz runtime
  exits use its JSON logger with only fixed service/liveness reasons. Nonzero
  exit, supervisor, listener closure, restart policy and cutoff clocks remain
  unchanged. Runtime-exit events remain visible through fixed hints; legacy
  plain service failures still fail with distinct categories. No malformed
  record is discarded or added to startup exceptions. Targeted Go 1.26.11
  tests and vet, 12 log tests, three heartbeat tests and 37 related checks
  passed. Fresh CI `43776402103` and installed run `43776401967` are pending.
  The earlier service-exit cause and original package-upgrade cause remain
  unproven; no installed upgrade is accepted.

The [local framing record](evidence/local-relay-log-framing/index.json) is
reproducible from a full clone using a local Docker endpoint and its cached
pinned build image:

```sh
python3 tools/handoff/reproduce_relay_log.py
```

It creates only one named, network-isolated, one-CPU/64-MiB container with no
published ports and removes that owned container. It does not install packages,
change host services or require sudo. The observed first fragment was 16384
bytes; two reads preserved the complete 20043-byte event. This local mechanism
experiment is not installed-appliance or public acceptance. Keep runtime tests
and result collectors in tmux; collectors must verify and skip completed local
receipts when restarted rather than redownload finished artifacts.

Local actual PostgreSQL checks at source `52e3362` also passed eight ordinary
top-level cases and the explicitly enabled bounded snapshot-load case. At 100000
revoked rows, 100000 rotation floors and 1024 tenants, the observed refresh was
460288 microseconds against the unchanged 1000 ms budget. Tenant overflow at
1025 was refused with the prior known denial retained; the owned isolated test
container was removed. The compiled CLI reports Go 1.26.11 and clean source
`52e3362`. The [closed local record](evidence/ubuntu-52e3362-local/index.json)
includes source/binary/log hashes and the four observed row-scaling cases.
These observations do not establish signed Ping throughput, online fleet
capacity, native/public cutoff, or complete W5 acceptance. Allocated-byte figures
describe allocations during a refresh, not steady resident memory.

The [complete `52e3362` checkpoint](evidence/ubuntu-52e3362/index.json) retains
33 closed files for all five runs, including the failed preflight, successful
source-bound producer/preparation/contracts/recovery and the 13 required console
images. Six images match already reviewed bytes; seven changed views were
reviewed. The continuation verifier checks original archive digests, run
identities, all 257 contract source blobs and the distinct failed/native versus
passed/isolated outcomes. It does not reinterpret the old ambiguous `tls` label
as proof that the failed operation was a TLS handshake.

The documentation branch's source `59dedf0` CI `43731180948` failed an unchanged
combined-fault reference-route check after revocation. Its observed cutoff timing
does not turn that failed scenario into a pass. No tested-image archive was
accepted from that run. The Docker-only quickstart also needed an explicit base
doctor invocation using the same image and read-only absolute state/backup mounts;
the host CLI is not installed by running the initializer container.
Later documentation source `0420594` passed all six jobs in CI `43760561493`
and its separate FreeBSD check. That separate success does not diagnose or
relabel the earlier combined-fault failure, and its images are not used for
the `52e3362` native run.

The [first Ubuntu evidence index](evidence/ubuntu-870eb57/index.json) is durable
and independently checkable with `python3 tools/handoff/verify_continuation.py`.
The original handoff verifier remains required and all 29 original rows remain
unchanged. These offline integrity checks do not execute a runtime acceptance.
The [later preflight evidence index](evidence/ubuntu-native-preflight/index.json)
retains 16 closed files for six runs, explicitly separated between sources
`38bec4d` and `b2bfb50`. The same continuation verifier checks the native failure
stages, source-specific CI bindings, original ZIP digests and isolated recovery
cleanup. Private logs and credentials are not included.

The [structured-exit checkpoint](evidence/ubuntu-d33302f/index.json), source
`d33302f5420f6d90cc04b7e5142bc9660569d987` in
[PR 251](https://github.com/KazuhaHub/nethub/pull/251), retains another 33 closed
files for five exact-source runs. Unexpected runtime exits now use the existing
JSON logger with fixed reason categories and no raw error; the nonzero exit and
fail-closed policy remain unchanged. Six-job producer `43776402103`, preparation
`43776401980` and filesystem contracts `43776401969` passed. All 258 contract
source blobs, the complete preparation source archive, compiler/frp pins and
required image hashes were checked. The 13 producer views include six identical
previously reviewed images and seven changed reviewed views.

Installed run `43776401967` failed earlier at the genuine fleet steady-window
original control socket identity comparison (`relay_fleet.py:133`). Its closed
report has no failure hints and confirms owned-image cleanup. No guest was
created; neither runtime-exit classification nor package migration was reached.
The socket-change cause, earlier service-exit cause and original upgrade cause
remain unproven. Preserve this failure alongside all earlier failed runs.
Isolated cold recovery `43776401975` passed against the same producer/source:
baseline recovery 90741 ms, original-request initial issuance 164366 ms from
source stop, checkpoint-to-issuance 175234 ms, with cleanup confirmed. Both
masked views were reviewed. Public custody, renewal and full acceptance remain
explicitly false.

[PR 252](https://github.com/KazuhaHub/nethub/pull/252), source
`ea173c660a38bd6c61f37f013e58761da4f337ae`, retains the fleet comparison and
refusal while adding closed stage and original/dedicated-client categories plus
bounded existing-log presence hints. Passing comparisons perform no new reads;
diagnostic failure cannot hide the original refusal. Four fleet tests, twelve
log-reader tests, three heartbeat tests and 38 projection/provenance tests
passed locally. All five exact-source gates subsequently passed: six-job
producer `43783251653`, FreeBSD `43783251552` (252 cases and 258 verified Git
blobs), preparation `43783251640`, installed `43783251698` and isolated cold
recovery `43783251668`. The [complete checkpoint](evidence/ubuntu-ea173c6/index.json)
retains 35 closed files with original ZIP digests and source/run identities.

Installed acceptance completed all ten native package phases: old-package
rollback, legacy recovery and 37.229-second steady window, upgrade to the current
package, current recovery and 12.409-second steady window. The eight invariant
flags passed and the fixed failure list is empty. Model/GUI/runtime/trust,
source grants, the independent witness process and the other five services were
retained. The final current profile and original relay configuration were
restored. There was no manual agent start/reconcile or replay of package/SQL
mutations. One recorded `package_snapshot` inspection recovered the owned SSH
listener after a connect timeout and completed its read in 10657 ms under the
existing bounded read-only policy; this is not a package-operation retry.

The actual normal console-confirmation-to-native-proxy cutoff was 1952 ms;
fresh verified TLS was refused with the valid source grant retained, the original
reference control/TLS survived, and the no-reconnect window was 30068 ms.
WAN change and restoration measured 4573/4563 ms in the hosted fixture.
Normal/interrupted Rotate, trust publication and committed replay, shared-token
recovery, six-service restoration, native Remove and the complete Compose tail
passed. Guest exit was zero and owned-image cleanup was confirmed. All fourteen
native image hashes and nine distinct masked views were checked. Isolated cold
recovery retained original identity/account/key/CSR/Open and passed normal Remove:
baseline route recovery 89214 ms, original-request issuance recovery 163250 ms
from source stop, checkpoint-to-issuance 174631 ms.

This qualifies the current source's isolated native package gate for subsequent
doctor integration. It does not identify which comparison failed in historical
`a29`, attribute that failure to the independently reproduced install-guard race,
or relabel any earlier failed run. The public/mobile/operator, published package,
independent deployment, renewal/custody and canary gates remain open. Overall
acceptance flags remain false. Integrate only the doctor feature patch on this
validated source, then collect fresh exact-source evidence for the changed tree.

The English/Chinese README entry points and documentation index now distinguish
the dated Ubuntu handoff from this continuation record. A partial semantic review
covered those entry points and the eight operation guides for heartbeat
revocation, console Revoke, Open, disconnect requests, device rotation,
shared-token replacement, relay maintenance and anomaly confirmation. Their
scoped evidence, independent access, retained-journal and public/mobile/release
limitations remain explicit. This does not complete the review of every document,
external-reference checks, final integrated-source correspondence or the
independent ten-minute deployment requirement.

Further partial review covered the protocol walkthrough/schema guide, OIDC
login/providers, provider encryption, invitations, and SAML
login/providers/metadata/dependency notes. The SAML metadata guide now labels its
old authcore pin as the preparation checkpoint; the active graph remains the
existing `c1447857d71b` pin and explicit interim parser replacement. The dependency
record distinguishes its early unaccepted cold-recovery checkpoint from PR 223's
later isolated acceptance. Live PR inspection still found authcore PR 37 open and
draft at `e3e8cc05330fcff6cbd21c6f38e10320a165c0e1`. No dependency change or new
security/advisory acceptance follows from this documentation review.

Further partial semantic review covered audit-chain verification, console audit
visibility, traffic accounting, scheduled backups, external-proxy deployment,
user administration, relay-authority operations, credential-history checks,
security-validation history and the threat model. The threat model now also
links the later source-bound isolated 1952-ms result while retaining historical
failures and public/mobile limitations. The existing continuation branch already
records the owner's waiver of the third company/campus sample. This review does
not accept every document or replace current dependency/advisory checks or an
independent operator.

Further reading covered the OPNsense agent and plugin guides, platform capability
and FreeBSD-contract scope, deployment/server entry points and relay-trust,
rotation and historical frp-hook protocol notes. The rotation guide's old
five-second cache description was reconciled with actual `RevocationInterval`
and `RevocationMaxAge`: one-second refresh, 2.5-second expiry and freshness
fail-stop, with no instantaneous or public/mobile guarantee. The historical
0.71.0 hook observations remain distinct from the current 0.71.1 pin.

## Doctor integration and the first real provider sample

PR 253 applies only the retained external TCP feature on qualified native source
`ea173c6`, preserving the later native/transport fixes. Its source
`16708e35443fbbe93344bd897f8d5ab3ef6749d0` passed six-job CI `43791395178`,
FreeBSD `43791394959` (252 cases / 258 blobs), preparation `43791538230` and
isolated cold recovery `43799098898`. Cold archive digest, source operation and
cleanup validators, both image hashes and the changed view were checked:
baseline route recovery 108774 ms, original-request issuance/native acknowledgement
156059 ms from source stop. Installed `43799096360` subsequently completed successfully. The
[complete source-bound checkpoint](evidence/ubuntu-16708e3/index.json) retains
34 closed files, official archive digests and all five exact-source run identities.
All ten package phases, eight invariant flags, legacy/current steady windows,
original witness process, source grants and other five services passed. Legacy and
current steady windows were 37307/11475 ms. Normal console-confirmation-to-native
proxy cutoff was 1225 ms; fresh verified TLS refusal, independent original
control/TLS retention and a 30081-ms no-reconnect observation passed. WAN change
and restoration measured 3458/4456 ms in the hosted fixture. Normal/interrupted
Rotate, trust conflicts and committed replay, shared-token recovery, six-service
restoration, normal native Remove, complete Compose tail and owned cleanup passed.
Fourteen image hashes and nine distinct views were checked. One read-only
`inspection_preflight` SSH timeout recovered the owned listener and completed its
read in 10379 ms; no package or SQL mutation was replayed.

This qualifies only that source's isolated integrated-native scope. The historical
`a29` failed comparison remains unidentified, its earlier failed runs stay failed,
and neither this result nor the real TCP negative qualifies changed source
`898c3e0` or consolidated candidate `109aab5`. Their exact-source gates remain
separate; public/mobile, formally published package, independent operator,
renewal/custody, signing and canary requirements remain open.

The first real compiled doctor call refused the provider's extended report before
interpreting any closed port. A separate Python diagnostic received HTTP 403;
that failed observation remains retained. A bounded diagnostic with the same Go
HTTP client established the genuine TCP shape: `host` contains the IP and `port`
is a separate decimal string. Command, creation time and all three observer
identities matched. The original fixture had incorrectly embedded port in `host`.

PR 254, source `898c3e0e474aaf03c294c78c37d9e6c96630b6fb`, checks both separate
fields exactly. Five added denial subcases cover wrong host and wrong, missing,
numeric or noncanonical ports. The parent production parser fails the corrected
positive fixture using a read-only Go overlay; the fixed tree passes 41 top-level
Go externalprobe/CLI cases, formatting, vet and build with pinned Go 1.26.11,
networking disabled and two CPUs. Ten native/transport/pin files remain identical
to the isolated-native-qualified parent. Fresh exact-source gates are pending.

The clean source-bound binary subsequently accepted the genuine report binding
and refused TCP 443 because an external observer could not connect: exit 1,
3682 ms, empty stdout. This is a real owned-host negative sample. Fail-fast means
7000/8443 were not reached; no all-port positive, TLS, published-package, public
W5 or full W7 result follows. The [closed diagnostic checkpoint](evidence/external-tcp-report/index.json)
contains no raw provider response, target connection metadata or credentials.
Earlier mismatch/403 failures remain failures. A later read of the already
retained Go diagnostic request, without a new submission, confirmed its original
creation time, exact TCP-443 target, unchanged three observers and three final
failures with no successful connection time. This corroborates the closed-port
provider observation; it is not an all-port negative or positive sample.

A separate one-vCPU/one-GiB owned libvirt fixture passed signed Canonical image,
upload hash, pinned SSH host key and NAT-local TCP checks, then shut down. It
changed neither the default NAT definition nor public forwarding. Its readiness
is not a public sample or hosted native acceptance. Public port-forward root
commands remain skipped for the owner; the fixture is powered off meanwhile.

## Consolidated Ubuntu candidate

The `chore/ubuntu-continuation-integration` branch combines PR 254's strict
provider correction, the continuation documentation/evidence and PR 244's portable
runtime prerequisites. The merge brought documentation, closed evidence and
verification/reproduction tools only; native/transport fixes remain intact.
The portable helper now defaults its console/Go test containers to two CPUs,
bounds Go build parallelism and retains private build/module caches. No accepted
image archive from another source qualifies this candidate. Collect fresh
exact-source producer, FreeBSD, preparation, installed and cold-recovery gates
before accepting its applicable runtime scope.

The local portable-helper attempt stopped at prerequisite admission with exit 2:
PHP is absent. No tests or deployment were started by that attempt, and it is not
a successful local suite. Host package installation needs the owner under the
shared-server rules. Continue other read-only, container and hosted work while
that prerequisite is skipped; do not remove the admission check.

A further partial semantic review of 32 component/deployment/acceptance guides is retained
in the [source-bound review inventory](evidence/semantic-review-109aab5.json).
It covers device admission/lifecycle/rotation, durable CSR and issuer roles,
ACME account/order/challenge/finalization/renewal, protected issuer work and relay
authority/trust/maintenance/probes/state/token boundaries, plus initializer and
console entry points, certificate automation, the detailed installed/cold-recovery
histories and database foundation records. The certificate overview now links the
merged isolated protected-host recovery while retaining public/operator,
renewal-clock and durable-custody gaps. It does not complete every document, external-reference
verification or independent ten-minute deployment. The quickstart now passes the
operator's selected `--network-subnet` in both initialization examples; otherwise
the CLI silently uses its documented default despite that selection instruction.

## Temporarily skipped owner-dependent actions

| Requirement | Missing input or participation | Resume condition |
| --- | --- | --- |
| Local complete portable helper | Host PHP CLI/XML are absent; prerequisite admission returned exit 2 before tests. Host installation needs owner `sudo`. | Owner runs `sudo apt-get install --no-install-recommends php-cli php-xml`, then rerun the unchanged full helper on the selected source. Scoped component/hosted results do not relabel this stopped attempt. |
| Public ingress, W7-3 external TCP, W7-5 public recovery | Historical LXC/DNS access remains undelivered. The current owned-host TCP-443 negative sample passed after the report-shape fix; a NAT-only fixture is ready and powered off. No public forwarding was added. | Owner runs reviewed `sudo vm-forward` additions/removals for the positive TCP sample in a controlled window, or privately delivers another owned endpoint. Separate DNS/public TLS and full public operator recovery still require their own resources and evidence. |
| W5/W7 mobile and source grants | Two historical carrier samples do not cover the new flow; a real phone and operator session are needed. | Arrange fresh mobile Open/login/refresh/revoke observations after the integrated native source qualifies. The third company/campus sample remains explicitly waived. |
| W6-6 public provider | No registered public IdP test application or operator-controlled credentials have been delivered. | Register a suitable public test app and privately provide its credentials; retain invitation, identity-binding and denial/replay cases. |
| W7-9 formal router install | The actual published package and a fresh public/mobile operator session are unavailable. Existing hosted guests cover only their unsigned isolated scope. | Use an approved non-production device with independent recovery; a new local lab can be provisioned within the shared-host limits without transferring the old Windows VM. Qualification still requires the actual signed package and genuine public/mobile observations. |
| W7-9 independent deployment | No separate participating operator is confirmed. | A real independent operator follows repository documentation on their own infrastructure and records gaps, enrollment and cleanup. |
| W7-8/D13 packaging, signing, publication and canary | Signing remains Kazuha's responsibility; no signing environment or authority has been delivered. | First pass the product gates, then prepare a concrete release candidate and independent packaging verification for the owner. Preserve runtime/signing separation and test canary rollback only on approved non-production devices. |
| W7-7/D12 final content decision | Owner review is still required; public repository visibility does not close it. | Prepare the complete content/disclosure review for an explicit owner decision. Preserve existing history. |

The new environment's test private key is outside the repository. Do not commit
keys, passwords, connection metadata, raw configuration or unmasked operational
material. No old Windows file is a prerequisite for source checks or hosted guests.

## Scope retained

All 29 original requirements and their acceptance ranges remain open or scoped
exactly as recorded until new evidence closes them. Keep the five-second revoke
target, frp 0.71.1 alignment, Go 1.26.11, authcore reuse and the confirmed security
boundaries. Native diagnosis precedes the external doctor integration; public,
provider, formal-package, independent-deployment and canary gates follow their
actual dependencies. Skipping an unavailable action never means accepting it.
