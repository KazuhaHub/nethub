# Device credential rotation

The device plugin now has an explicit **Rotate credentials** action and
`agentctl.py rotate`. The isolated installed native/relay workflow passed at source `986ee4c`
([run 40823820125](https://github.com/KazuhaHub/nethub/actions/runs/40823820125));
there is no accepted signed appliance release containing this feature yet.
Keep independent local access when testing it. Rotation can reconnect the tunnel.

The action retains the enrolled device, assigned subdomain, native GUI login,
certificate identity and local stop policy. It obtains the current relay
assignment over verified console HTTPS. A private journal persists its random
candidate and operation ID before any rotation request. Only an atomic server transaction
can replace the credential and claim. The native PHP model then saves that exact
assignment under its configuration lock and confirms the written XML. Python
does not write `config.xml`.

A fresh operation first synchronizes managed relay trust through its existing
verified transaction. Explicit rotation can refresh trust while locally disabled
or stopped, without releasing either condition. The periodic trust job still
leaves inactive devices alone. A retained rotation skips this refresh and keeps
its original snapshot until recovery completes.

If a request, model save or reconciliation is interrupted, retry **Rotate
credentials**. The retained candidate recovers an unknown committed response;
a received assignment retries without another server rotation. If the native
save was interrupted, retry still completes that save; a model already confirmed
at the candidate is not saved again.
The journal remains until the model readback and ordinary idempotent reconcile
succeed. Do not delete recovery files, edit credentials manually or re-enroll
to hide a failed operation. A conflicting local policy/configuration change
requires local review rather than automatic overwrite.

If removal is needed while a rotation response is unknown, **Remove enrollment**
can retry revocation with the bound saved candidate after stopping the tunnel.
It keeps the journal until the server confirms that exact device is revoked and
the native model is cleared. A remaining rotation journal prevents enrolling a
different identity over unresolved recovery state.

The shared mutation lock excludes reconcile, watchdog and other device actions
while rotation runs. The command and backend have internal and external time
limits. The console page receives only a fixed success/busy/saved/error result;
credentials and native snapshots never appear in browser responses, process
arguments or diagnostic messages. The root-only PHP model helper exchanges its
private data over stdin/stdout with the bounded Python caller.

Interactive Rotate acquires that same lock inside the agent rather than in an
outer `lockf` process. It waits up to three seconds for a short scheduled
operation to finish, before trust lookup, journal creation or network access.
Longer contention returns the existing fixed busy response. Retry explicitly
after the other operation finishes; no rotation request is replayed while waiting.
Scheduled jobs and other mutation actions retain nonblocking admission. The
existing outer command/backend deadlines still include this bounded wait.

The installed run at source `9d8695d`
([run 43365524345](https://github.com/KazuhaHub/nethub/actions/runs/43365524345))
failed when retrying a received assignment after the controlled native-save
interruption. Its response was HTTP 200 with `success=false`, `phase=busy`.
The valid received journal and original model remained; a later lock probe found
no holder, so the original holder is unknown. That complete run remains failed.
The bounded-wait change above still requires native execution, including both
short contention recovery and long contention refusal. It does not change the
separate five-second console revocation target.

An error response may also contain a fixed `failure_reason`: `backend_response`,
`backend_exception`, `trust_sync`, `trust_recovery`, `native_model`,
`rotation_journal`, `native_save`, `interrupted` or `unclassified`. These categories
help distinguish unavailable backend output from trust, model and journal
failures. Unknown backend messages remain private. A category does not prove
whether a remote commit occurred; retain recovery state and use the same action
to recover it.

The saved disabled flag and local circuit/stop markers remain unchanged. A
revoked device or one undergoing removal cannot rotate. The action does not
grant source-IP access or bypass the router's own login. Old credential/claim
admission is rejected by the database after commit; existing controls learn a
monotonic issuance floor through the heartbeat snapshot refresh. The refresh
and last-good failure policy mean cutoff is not instantaneous.

Relay CA/trust-generation changes belong to the existing verified trust
transaction. This action refuses to overwrite that managed trust metadata or
silently substitute a different CA. A pending rotation with changed local trust
or policy remains retained for review. Periodic trust synchronization defers
while a validated rotation journal remains; malformed retained state blocks it.
This prevents background updates from invalidating the recovery snapshot.

New operations pin the exact native public CA bundle by SHA-256. A different
published bundle is refused before credential mutation; only that definitive
old-credential refusal releases a prepared journal so verified trust sync can
run. Ambiguous failures and candidate-attempt errors retain the journal.
Committed operations retain their public bundle for identical replay across
later publication. Publication fencing and synchronization retain separate SQL
and source-contract checks. The installed workflow above covers response loss
and native save-lock recovery. The subsequent
[installed publication-conflict combination](validation-native-trust-conflict.md)
passed definitive precommit refusal, native synchronization and one fresh
candidate. [Committed replay after a later publication](validation-native-trust-conflict.md#committed-replay-after-a-later-publication)
also has scoped installed acceptance in PR #212; changed sources still need their
own applicable regression checks.

This per-device workflow is only part of W7-4. Coordinated deployment-wide frps
shared-token replacement, current-key backup/manifest transitions and online
native/reference recovery have separate [scoped acceptance](validation-shared-token.md).
Offline devices in a forced replacement window require manual re-enrollment,
as recorded in the incident procedure. Public-network incidents, an offline-fleet
drill and release acceptance remain open. Isolated clean-host and protected-host
restoration have [separate acceptance](validation-protected-host-cold-recovery.md);
public operator recovery and durable off-host custody remain open.

## Lock-handoff validation

PR #224 merged as `50f591f` from source `5f1b344` with the tested tree unchanged.
Six-job [CI 42715789184](https://github.com/KazuhaHub/nethub/actions/runs/42715789184)
and all independent prerequisites passed. The FreeBSD suite ran 216 actual cases,
including a real scheduler `lockf` holder, structured busy response before any
mutation, and a separate explicit action after release. The lock, scheduler
exclusion and existing operation deadlines were preserved.

[Installed run 42715788756](https://github.com/KazuhaHub/nethub/actions/runs/42715788756)
passed normal rotation, lost-response and native save-lock recovery, publication
conflict/synchronization, committed replay after a later publication, shared-token
recovery, six-service restoration and genuine Remove with the complete tail.
Committed replay recovered in 5.493 seconds; restoration recovered both original
routes in 60.826 seconds. Exact source, all 37 official artifact entries, both
complete logs, guest exit zero, owned cleanup, thirteen image hashes and ten
unique actual views were checked. The native footer clips lower Remove content;
independent model, SQL, service and route evidence verifies removal.

Earlier failed installed runs remain retained and unaccepted. Reproducing the
exception/outer-lock handling gaps and passing this source does not establish
their exact causes. These isolated outcomes do not complete public/mobile/operator,
offline-fleet, signed-release or the remaining W5-W7 acceptance.
