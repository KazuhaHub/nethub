# Device credential rotation

The device plugin now has an explicit **Rotate credentials** action and
`agentctl.py rotate`. The combined native/relay workflow is under validation;
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
a received assignment retries without another server rotation or model save.
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
later publication. The new publication/recovery path is under combined
validation; source changes alone do not establish installed-device acceptance.

This per-device workflow is only part of W7-4. Coordinated deployment-wide frps
shared-token replacement, protected current-key backup/manifest transitions and
its incident procedure remain open. Offline devices in a forced replacement
window require manual re-enrollment, as recorded in the plan. A successful
per-device button test does not establish fleet incident recovery, complete
clean-host restoration or release acceptance.
