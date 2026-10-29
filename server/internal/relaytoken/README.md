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
  file/directory writes. Its root filesystem tests still require actual Linux
  execution; source and cross-compilation do not prove durability. The read-only
  material verifier checks exact before/after trees, the original backup and
  an independent successor containing current relay material and maintenance
  state. Its Linux fixtures are not yet accepted execution evidence. Snapshot
  construction, synchronization and live publication remain unfinished.
- The shared host lease and persistent admission against unresolved token and
  authority operations, including a crash after publication releases its lease.
- Exact two-file token replacement, manifest/ownership transitions, and a
  complete independent successor backup verified before live publication.
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
