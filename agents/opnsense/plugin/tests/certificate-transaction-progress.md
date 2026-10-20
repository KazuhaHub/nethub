# GUI certificate recovery journal foundation

`certificate_transaction.py` defines the durable ordering required by the native
GUI adapter. It is not connected to the scheduled certificate action and cannot
modify an OPNsense GUI by itself. The installed appliance stays on 0.0.6.

The caller holds the existing mutation lock and independently verifies the
staged public delivery. A native backend must prepare an immutable protected
snapshot without changing configuration; its public response contains only the
snapshot hash, owned refid/native-entry hash and GUI port. Snapshot keys never
cross that response boundary. The snapshot and containing directory are flushed
before a canonical `prepared` journal is atomically persisted. Native install
must fence the expected owned entry/certref, preserve unrelated configuration and
make its writes durable before returning. Only a positive GUI probe and a final
native selection check permit the journal to enter `applied`.

Ordinary failures attempt rollback; process death leaves `prepared`/`written`
evidence for independent recovery before the GUI starts. Recovery does not
create a key or contact the console. Native rollback must accept only the exact
before/after owned state and refuse to overwrite an operator's conflicting
selection. An unconfirmed rollback retains pending evidence and needs local
recovery instead of marking the transaction complete.

Each immutable issued generation has at most three persisted attempts, separated
by five minutes. Protocol metadata changes cannot reset that budget or reinstall
an already applied certificate. Generation identities cannot regress or change
material. A new generation records the previous applied native identity as
last-good. Retired snapshots are removed only after the replacement snapshot and
its exact retirement references are durable; hashes, ownership, modes and link
counts are checked before each unlink. Unknown preparation remnants are retained
for review and capped at eight files instead of growing without bound.

Fault tests use a fenced configuration model and real local journal files. They
cover interruption after native write and after the written marker, startup
recovery, failed probes, persisted retry limits, operator conflicts, changed
candidate/snapshot/journal bytes, failed journal replacement, retirement and
POSIX permission/symlink checks. These are transaction and filesystem proofs,
not native import, GUI reload, reboot or public HTTPS acceptance. The actual
OPNsense adapter, early boot hook, scoped lab watcher extension and guarded live
installation still need implementation and evidence.
