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
  any guard, operation or replay policy. Its 151 focused tests passed; fresh
  exact-source CI and installed acceptance are pending. This does not identify
  the historical upgrade cause or accept either earlier failed installed run.

The documentation branch's source `59dedf0` CI `43731180948` failed an unchanged
combined-fault reference-route check after revocation. Its observed cutoff timing
does not turn that failed scenario into a pass. No tested-image archive was
accepted from that run. The Docker-only quickstart also needed an explicit base
doctor invocation using the same image and read-only absolute state/backup mounts;
the host CLI is not installed by running the initializer container.

The [first Ubuntu evidence index](evidence/ubuntu-870eb57/index.json) is durable
and independently checkable with `python3 tools/handoff/verify_continuation.py`.
The original handoff verifier remains required and all 29 original rows remain
unchanged. These offline integrity checks do not execute a runtime acceptance.
The [later preflight evidence index](evidence/ubuntu-native-preflight/index.json)
retains 16 closed files for six runs, explicitly separated between sources
`38bec4d` and `b2bfb50`. The same continuation verifier checks the native failure
stages, source-specific CI bindings, original ZIP digests and isolated recovery
cleanup. Private logs and credentials are not included.

## Temporarily skipped owner-dependent actions

| Requirement | Missing input or participation | Resume condition |
| --- | --- | --- |
| Public ingress, W7-3 external TCP, W7-5 public recovery | Historical LXC/DNS resources exist, but Ubuntu has no delivered connection metadata, authorized SSH identity or independently verified host trust. | Privately deliver access to an owned disposable endpoint and DNS; authorize the new environment's dedicated public key. Recheck listeners and public reachability before any mutation. |
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
