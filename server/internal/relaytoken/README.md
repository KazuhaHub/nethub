# Shared relay token transition core

This internal coordinator preserves one incident operation across ambiguous
publication, reload and journal responses. The Linux host command is implemented
and remains under isolated acceptance testing; see the
[incident procedure](../../../deploy/shared-relay-token-rotation.md).
Server completion does not establish online-device or native incident recovery.

The intent binds a canonical operation ID, original deployment/service digest,
immutable snapshot digest and distinct previous/candidate token digests. There
is no plaintext token, password or signing material in this interface. A
concrete host must preserve the same candidate and original input before any
live mutation; resumption must not discover a new baseline from mixed state.

The coordinator persists and independently reads back intent/state before live
effects. Its phases are prepared, publishing, published, reloading, verifying
and complete. A lost publication response retries the same idempotent publish;
a lost reload response retries the bound reload. Verification failure retains
the verifying phase. A completed retry observes current runtime again and never
republishes its older material. There is no rollback to the compromised token.
Cancellation retains the durable phase preceding an ambiguous effect. Errors
return one fixed diagnostic rather than provider output.

The concrete integration still has to implement and test:

- The Linux journal adapter in `setup` now uses the existing protected file
  helpers, no-replace intent publication, atomic phase replacement and synced
  file/directory writes. Root filesystem checks passed at the scoped checkpoint
  below; they do not establish power-loss durability or host incident recovery. The read-only
  material verifier checks exact before/after trees, the original backup and
  an independent successor containing current relay material and maintenance
  state. Its Linux fixtures use synthetic material. Preparation now retains
  immutable request options, an OS-random candidate and an exact baseline before
  copying the complete before/after material and independent successor. Each
  copy uses no-replace atomic publication and file/parent synchronization;
  interrupted copies resume only with the same bytes. Changed baseline, binding,
  links or conflicting backup material are refused and retained for local review.
  The constructor passed seven actual protected-root cases (35 total required
  case identities) at source `03a197d` in run `40824419031`. The exact-source
  validator, official log and bounded receipt were independently checked. It changes no active
  file or service by itself. The host command now calls it under the shared
  lease; full incident runtime acceptance remains unfinished.
- Persistent admission now refuses partial or nonterminal token operations even
  after their process lease is released. Ordinary authority checks, relay
  maintenance and authority transition/preparation/cancellation enforce it. Only
  canonical, protected, operation/deployment-bound complete journals release this
  guard. Source `b078c62` passed 56 actual protected-root case identities in
  run `40825646677`, with exact-source validator/log/receipt checked. Review
  found that the new canonical-path guard broke relative authority-check input,
  including doctor's default directory. The wrapper now resolves relative input
  before admission. Source `3a302d7` passed all 57 required actual root case
  identities in run `40826372112`, including that relative-path regression; exact
  validator/log/receipt were independently checked. The token host
  caller acquires the shared lease and admits its own exact recovery request
  against other pending operations; actual command execution remains pending.
- The protected file publisher now requires the exact durable intent and
  publishing phase, independently verified snapshot/backup and known live
  before/after bytes. It changes only the two tokens and then the manifest,
  re-syncs acknowledged bytes, and refuses completed journals or unknown material.
  Cancellation after each real file replacement is covered by new root cases;
  these passed at source `c0eb283` in run `40824974675` (47 required root
  case identities). The exact-source validator, official log and bounded receipt
  were independently checked. It does not reload services or claim
  admission/recovery completion.
  The pure manifest planner now restricts changes to the two token digests and
  a disjoint successor-backup path, retaining deployment identity, owners and
  unrelated authority/credential entries. Its local tests do not establish
  protected file publication, an actual backup or runtime recovery.
- A private runtime host now gates reload on the exact retained publishing
  history, original-input digest, independent backup and all candidate live bytes.
  It reuses the bound two-service reload primitive, verifies the served leaf and
  performs candidate/previous/candidate Login checks using a read-only existing
  device identity and the deployment's existing claim key. No fixture device is
  inserted. These callbacks still need actual runtime acceptance. New root
  material/own-recovery gates passed all 78 protected case identities at source
  `3c5f13a` in run `40833147236`; exact-source validator/log/receipt were checked.
  Those are synthetic file/phase checks, not service acceptance. The command must verify
  retained input and hold the shared lease before using exact own-recovery
  admission; other pending token and authority operations remain blocked.
- Normal online-agent assignment recovery and the accepted forced-window
  procedure for offline devices, with native installed execution evidence.

Unit tests exercise lost effect/journal acknowledgements, cancellation, changed
request/snapshot/state, orphaned records and unconfirmed write readback. Their
host and journal are logical fixtures. They establish coordinator ordering and
recovery choices; they do not establish filesystem durability, real service
reload, incident recovery or complete W7-4 acceptance.

Actual Linux root checkpoint: source `b0dc115` passed 27 cases without skips in
[run 40816958107](https://github.com/KazuhaHub/nethub/actions/runs/40816958107).
The exact-source validator, complete official log and bounded compiler/binary/case
receipt were independently checked. The first run failed because the fixture
did not explicitly protect its backup parent; that failure remains retained.
The correction sets the test parent to 0700 and preserves production checks.
These are protected filesystem fixtures with synthetic bytes, not valid live
certificates, a restored control plane or recovering devices.


The standalone Login verifier passed genuine official-frps/authz valid/wrong/valid
admission in source `d6da675`, CI `40829521750`, with both original official-client
controls and verified TLS preserved. All six CI logs and that closed outcome were
independently checked; the protected root receipt in `40829521725` passed 57
required identities. The earlier source8 compiled cutoff wait failure is retained.
Its original delay is unconfirmed; the corrected test covers the next five-second
tick plus both independent two-second production budgets and exports only fixed
failure counts. The compiled cutoff case passed in source10. This validates the
Login primitive, not an actual deployment-wide token change.

The new Linux `relay-token` command retains immutable original input before
creating its operation directory. This retained record fences ordinary work even
after a crash during initialization. Rotate/resume hold the shared lease and bind
publication/reload to that original service identity; inspect reports historical
state without claiming fresh verification. New command-record cases expand the
required root set to 92. The real Compose harness now invokes the compiled host
CLI, verifies only authz/frps are re-created, retries completion without another
reload, then rotates both online reference clients with their existing bearers
and checks both original assigned HTTPS routes. Actual execution of these new
cases and genuine installed native shared-token recovery remain pending.

Source `3c5f13a` passed all six CI jobs in `40833147251`; complete logs, the
compiled cutoff and official-frps Login primitive were independently checked.
That evidence predates the host-command cutover harness and cannot accept it.
