# Native GUI application coordinator

The 0.0.9 source connects verified staging to the native transaction/backend.
Pending work is recovered under the shared mutation lock before checking
disabled/revoked intent. Material is revalidated against the local key and
independent managed trust immediately before application. Missing keys never
regenerate. Certificate failures have separate status and do not restart frpc.

The backend invokes the fixed PHP CLI through bounded stdin/public identifiers,
checks closed reply fields and hides child diagnostics. It restarts only the GUI
with the native script and no renewal arguments. Loopback TLS must verify the
same independent CA bundle, assigned hostname and exact leaf fingerprint, then
receive a bounded successful/login/redirect GET status line. No credentials are
sent or redirects followed. Trust-file changes during context setup are refused;
legitimate UTF-8 PEM comments are preserved.

Read-only native baseline checks exposed a method restriction before any GUI
mutation: the same pinned loopback listener returned 403 to HEAD and 200 to GET.
The probe therefore uses GET and closes after the bounded status line, without
retaining a response body or cookies. A TLS fixture reproduces HEAD rejection;
real 403 responses remain failures rather than being accepted as healthy.

PR #92's exact clean source passed 277 native tests and built unsigned 0.0.9.
That evidence predates this method correction. The corrected source needs its
own exact-head validation. The existing GUI leaf was pinned for baseline checks;
those checks do not prove hostname validity or installation of a new chain.

Ordinary rollback confirms idempotent native restoration, including one retry
after an uncertain save/reply. It repeats the GUI restart even when config was
already restored: a previous attempt may have died during restart. Boot recovery
does not restart/probe the GUI or contact the network. A package-owned early hook
runs bounded recovery before GUI startup; the builder includes executable mode.

The certificate task has a 35-second internal deadline inside a 45-second outer
bound, leaving compensation time. The early hook has a 20-second outer bound.
All use the persistent mutation lock. Package pre-removal recovers pending work
in running mode under that lock; failure aborts removal before service shutdown
or deletion of recovery tools.

Confirmed removal recovers pending work, then deletes only known hash-verified
runtime snapshots/journals. A persisted `removing` phase permits retry after any
deletion and blocks application. Unknown remnants remain for review. Installed
independent native certificates/keys are retained. New enrollment waits for old
runtime cleanup instead of silently reusing its request/ownership state.

The assigned name must already be allowed exactly: the existing primary hostname
or a manually entered Alternate Hostname. This matches installed native checks;
neither hostname fields nor security checks are modified. Other names return a
closed actionable prerequisite before configuration changes.

Tests cover real TLS/HTTP with private roots, fenced PHP models, restart/reply
loss, startup locking, removal interruption, enrollment cleanup and executable
package-removal ordering. They do not establish actual Core GUI application,
reload or reboot. Installed 0.0.6 stays unchanged until the scoped watcher is
extended and rehearsed. Guarded live/public pipeline evidence, applied-generation
acknowledgements, renewal authorization and trust transitions remain required.

The first guarded live 0.0.9 attempt stopped during preparation, before any GUI
certificate/ref save. Native Core owns its configuration through the service
account configured by AppConfig, rather than necessarily root. The guard restored
the original model, all 18 owned files, package 0.0.6 and pinned GUI access, then
closed and removed its temporary boot hooks. This failed attempt is not GUI
application acceptance.

The 0.0.10 correction resolves Core's configured user/group from protected local
account databases, without requiring the optional PHP POSIX extension. The CLI
supplies that identity from Core AppConfig; it never comes from HTTP input or the
plugin model. Only the native configuration file may use that service owner and
exact group. Root-owned plugin keys, snapshots and directories retain their
existing ownership checks; links and public configuration modes remain refused.
Native tests cover the installed configuration metadata without mutating it,
service-owned synthetic XML and rejection of wrong user/group/mode/key ownership.
The focused working-tree native run passed 112 cases; exact committed-source and
live GUI acceptance must be recorded separately.


## Native acceptance checkpoint

Exact committed 0.0.10 source `8a3cf5056a7faf24b403f99364a2ab3731c06d0c`
passed 291 native cases and built the unsigned package identified in HANDOFF.
That package then passed actual Core import, independently trusted
CA/hostname/leaf/GET confirmation, idempotence and rollback from an injected
second-generation confirmation failure. A separate process held both writer
locks with a durable prepared journal until a cache-flushing quick VM reboot.
After the boot identity changed, the product early recovery journal was rolled
back and the native selected entry matched last-good before lab restoration.
Stock early-hook ordering precedes ordinary GUI startup; recovery latency was
not separately measured.

Both experiments completed their guarded restoration to the original GUI/model,
System/unrelated tree, 18 owned files, stopped intent and package 0.0.6. Original
GUI TLS/HTTP and pinned SSH authentication pass. Package checksums pass; owned
processes, temporary hooks and GUI runtime paths are absent. The external test
issuer key was deleted. Native Core configuration backups containing lab entries
remain in the appliance's normal backup history; runtime cleanup is not erasure
of those historical keys. Root and GUI security settings stayed unchanged.

These are native private-CA proofs on the accepted 1 GiB test VM. Fresh combined
public HTTPS/native enrollment, applied acknowledgements, renewals and trust
transitions remain. Documentation after the tested source commit changes no
package or test code; its validation must retain the original artifact binding.
