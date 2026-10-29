# Shared relay token transition core

This internal coordinator preserves one incident operation across ambiguous
publication, reload and journal responses. It has no production caller yet.
It does not replace the missing protected host command, incident runbook or
online-device recovery workflow.

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
  file or service, and has no production caller. Host admission and live
  runtime integration remain unfinished.
- The shared host lease and persistent admission against unresolved token and
  authority operations, including a crash after publication releases its lease.
- The protected file publisher now requires the exact durable intent and
  publishing phase, independently verified snapshot/backup and known live
  before/after bytes. It changes only the two tokens and then the manifest,
  re-syncs acknowledged bytes, and refuses completed journals or unknown material.
  Cancellation after each real file replacement is covered by new root cases;
  these still require actual execution. It does not reload services or claim
  admission/recovery completion.
  The pure manifest planner now restricts changes to the two token digests and
  a disjoint successor-backup path, retaining deployment identity, owners and
  unrelated authority/credential entries. Its local tests do not establish
  protected file publication, an actual backup or runtime recovery.
- Reload and genuine admission/TLS observations for only the selected runtime
  services, without distributing authority private keys to containers.
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
