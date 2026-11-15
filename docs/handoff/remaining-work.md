# Remaining scope: all 29 requirements

This is the complete continuation ledger at the owner's stop request. P0-W4
implementation/history remains in PLAN and the stage records; work continues
through the W5-W7 and decision gates below. A scoped success does not establish
the complete milestone or a production release. Preserve earlier failures.

Start with the a29 native upgrade failure in [validation](validation.md), then
integrate the external doctor candidate and regenerate exact-source evidence.
Use [Ubuntu instructions](ubuntu.md) and the [decision/repository ledger](decisions-and-repositories.md).

| Requirement | State | Evidence scope | Next action |
| --- | --- | --- | --- |
| W5-1/mobile | pending | W0 phone feedback is historical, not the new console grant/signed-package flow. | Use a real mobile network for normal console Open, router login, refresh and a masked recording; record source and package scope. |
| W5-2/local-breaker | scoped-success | Earlier native/public breaker records are retained; no full release qualification. | Retain the local stop policy and test that affected package changes cannot let reconcile/watchdog reopen it. |
| W5-3/revoke-five-seconds | partial | Earlier native/public desktop timings and current isolated combined-fault results passed; latest native upgrade failed before later Revoke. | Fix native upgrade, then prove the complete normal confirmation-to-cutoff path within five seconds, fresh TLS denial, no reconnect and an unchanged independent reference; include mobile scope. |
| W5-3/SQL-and-memory | scoped-success | Real SQL snapshot/load bounds, overflow refusal, monotonic floors and role/admission cases passed. This is not an online fleet sizing claim. | Retain the source-bound limits and repeat affected checks after changes; measure larger online/public capacity separately if claimed. |
| W5-3/fallback | conditional | The owner retained the five-second target; heartbeat denial mechanisms have scoped successes. | Use a fallback only if required mechanisms cannot meet the target and the owner approves a changed design; do not silently substitute relay restarts. |
| W5-4/anomalies | scoped-success | Three-observation alarm and constrained action checks exist. CARP is labels/alarms only. | Retain bounded actions and revoked/disabled behavior; do not claim transparent CARP failover. |
| W5-5/source-grants | partial | Explicit normal Open grants and public desktop source checks passed; the new mobile flow remains open. | Verify the actual mobile source, fixed 30-minute grant and explicit renewal, without SQL-created grants or traffic-driven extension. |
| W5-6/reboot-restore-WAN | partial | Hosted WAN recovery and older local reboot/config restore are scoped successes. Latest a29 WAN substep passed before the upgrade failure. | Retain measurements with original identity/process/config/GUI; complete current formal-package/public operator coverage and record restore timing separately from scheduled delay. |
| W5-7/recovery-reminder | scoped-success | Native enrollment reminders and independent-access warnings were observed. | Keep the warning visible; revisit only when affected by UI/enrollment changes. |
| D6/load-and-faults | partial | Twelve genuine controls plus 99000 synthetic rows/floors, owned loopback loss, five cache phases and fourteen config-migration phases passed. | Resolve failed native rollback/upgrade acceptance. Preserve outage bounds and original references; do not promote these samples to arbitrary public loss, offline fleet rollout or large online-fleet proof. |
| W6-1/roles | scoped-success | Admin/member ownership, tenant and runtime SQL boundaries passed. | Retain actual SQL and browser role coverage under the final integrated source. |
| W6-2/invitations | scoped-success | Invitation-bound enrollment, expiry/one-use and authorization paths are implemented/tested. | Retain denial cases and exact issuer/subject binding; do not introduce email-only account linking or JIT provisioning. |
| W6-3/providers | scoped-success | Isolated provider management and two real Dex provider cases passed. | Keep secret exclusion, replay, issuer fences and signed false-claim tests; public-provider enrollment is a separate row. |
| W6-4/authcore | scoped-success-with-dependency-followup | Local/OIDC/SAML use authcore. NetHub explicitly repeats the reviewed interim SAML parser replacement. | Review authcore PR37 and current upstream advisories before changing pins; adopt reusable fixes in authcore rather than duplicate authentication logic in NetHub. |
| W6-5/audit | scoped-success | Actual SQL audit visibility, payload exclusion, role/redaction/pagination and browser fixtures passed. | Retain actual runtime-role reads and log exclusion in the final source; synthetic screenshots alone are insufficient. |
| W6-6/public-provider | pending-external-resource | Dex and Keycloak integration is real but isolated. No registered public provider/operator sample is accepted. | Register an appropriate public test application with operator-controlled credentials and exercise invitation, login, denial/replay and cleanup; keep credentials outside Git. |
| W7-1/chain | scoped-success | Versioned UTC audit encoding, serialized append and read-only corruption detection passed. No external anchor exists. | Keep existing history unchanged and document the external-anchoring limitation; reject corrupted history without repair or partial success. |
| W7-2/traffic | scoped-success | Real monthly SQL accounting and actual relay payload/browser warnings passed; figures are approximate. | Preserve monotonic/reset/month/tenant/role checks and warning-only behavior under final source; do not imply billing-grade totals. |
| W7-3/doctor | partial | Core initialization/DNS/TLS/roles/container/relay-hook/recent-dump modes exist. External TCP PR242 passed CI fixtures; no genuine public positive/closed-port sample exists. | Integrate the doctor patch after the native fix, run owned-public positive and closed-port samples, and implement/validate agreement with an actually published agent package version. |
| W7-4/rotation | partial | Earlier installed normal/interrupted Rotate, trust CAS/publication replay and shared-token recovery passed in isolated scope. | Retest the final source after the upgrade fix and complete public/operator/offline-device procedures. Keep original candidate replay/idempotency and manual offline reenrollment requirements. |
| W7-5/restore | partial | Current a29 isolated recovery passed: baseline108498ms and original issuance/native served route152101ms from source stop; cleanup passed. | Perform a fresh public-host/operator drill, establish encrypted durable off-host custody and recovery instructions, and observe real renewal timing; initial private-ACME issuance is not renewal proof. |
| W7-6/docs | partial | Repository deployment/threat/validation guides and this portable handoff exist; bounded link/disclosure checks are not a complete semantic review. | Read every document for current behavior and translations/external links; correct unsupported claims and verify the complete ten-minute path with an independent operator. |
| W7-7/D12 | pending-owner-final | The repository is already public by owner instruction; final content/disclosure review remains separate. | Prepare a concrete reviewed content decision for the owner. Do not rewrite history or treat a secret scan alone as the required owner review. |
| W7-8/D13 | pending | External packaging PR52 contains preparation only; no NetHub registry entry, signed candidate, tag or publication is accepted. | After product gates pass, create the real release tag/archive/SHA256/report; complete independent packaging verification, recipe/registry integration, signing, publication, canary and rollback with the owner. |
| W7-9/router-package | pending | Unsigned hosted and earlier approved local router checks do not qualify installation from the formal repository. | Install the actual published package on an owner-approved non-production router and complete enrollment plus mobile remote GUI access; preserve independent recovery access. |
| W7-9/friend | pending-independent-participant | Internal CI/fresh VMs do not replace a separate person using their own infrastructure. | Have the recipient or another independent operator follow only repository documentation on their own Ubuntu server and device; record steps, gaps, enrollment and cleanup. |
| W7-9/bad-canary | pending | No intentionally bad formally published canary/channel drill is accepted. | Use an isolated canary to demonstrate invalid config refusal, correct watchdog behavior, channel control and rollback; never use production routers for the deliberately bad package. |
| W7/final-CI-and-dependencies | partial | Both current six-job CIs passed, but both installed runs failed. PR241 dependency refresh and PR236 frp update remain unmerged. | Resolve native failure, review dependency/security scope and source licenses, integrate approved changes, then run all final exact-source gates. Do not close bot PRs or claim advisory-free status without evidence. |
| D14 | confirmed | Owner confirmed device mTLS deferral, no audit external anchor, signing/packaging host exception with runtime separation, and CARP alarm-only scope. | Preserve these boundaries; do not reopen them as routine implementation questions or imply stronger guarantees. |

## Resources the next operator supplies

Use a fresh disposable Ubuntu development host, a public Linux ingress, control
of the test DNS/wildcard, and an independent non-production OPNsense device with
recovery access. Public-provider credentials, signing authority and durable
off-host backup storage belong to their operator. They are deliberately not
project files. CI creates its own fresh guests and temporary credentials.

Two different mobile networks can be represented anonymously; W0's declined
third company/campus sample must not be invented. The new W5/W7 mobile flow
still needs its own actual evidence. Independent deployment and final owner
decisions require real people; automation cannot substitute for those outcomes.

The old workstation, relay session files, private screenshots, VM disks and
credentials are not prerequisites for this handoff. All required source,
protocols, tests, deployment templates, pending patches and instructions are in
this repository. Build new lab material and gather new evidence for changed code.
