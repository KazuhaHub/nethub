# Fresh installed appliance preparation

The preparation and failure history below describe their original sources.
Subsequent complete installed runs passed [device rotation](../../../deploy/device-rotation.md),
[shared-token recovery](../../../deploy/validation-shared-token.md) and
[merged clean-host integration](../../../deploy/validation-clean-host-restore.md),
including genuine native Remove and the complete Compose tail. These are isolated
unsigned checks, not public/operator or formal-release acceptance. Later source
changes still require exact-source execution.

`native-appliance.yml` owns a new hosted Linux/KVM guest. It verifies the pinned
official Nano image checksum, independently published release key and raw-image
signature, updates the guest's signed OPNsense packages, and builds the current
unsigned plugin with the pinned FreeBSD Go SDK and dependency locks. SSH host
trust is obtained through the verified guest's serial console. Both management
forwards bind to host loopback; no local workstation VM or existing relay is used.
The first emulated NIC is the restricted LAN and the second is the outbound WAN,
matching the signed image's factory `em0` LAN and `em1` WAN assignments. Factory
interface and firewall configuration remain enabled.

The installed frpc receipt, package registration, configd status and native page
are checked. The unconfigured device must show enrollment and keep rotation
disabled. This preparation does **not** accept enrolled rotation, real relay
cutoff/recovery, public TLS/network access, restoration or W7. Those checks still
need the same current package joined to the controlled deployment.

The factory GUI's self-signed certificate is allowed only for its initial private
page check. It cannot establish verified public/relay TLS. The guest receives
3072 MiB. Its disk, serial transcript, temporary SSH keys, build output and native
configuration remain private to the disposable runner. Only the closed result
and logged-in, unenrolled page images are uploaded. Scrolled mobile images also
check that the enrollment field and rotation control are unobscured in the native
shell's scroll container. No package is signed or published.

Source `340b73c` passed the [earlier preparation checkpoint](https://github.com/KazuhaHub/nethub/actions/runs/40801553084):
the unsigned package, rebuilt frpc 0.71.1 with Go 1.26.10, agent stopped status reported through configd
and unenrolled native page were checked on fresh OPNsense 26.7.7. The exact source
archive, official log and four image hashes/visuals were independently verified;
the owned guest terminated with exit status zero. Supplementary mobile viewports
confirmed unobscured enrollment and disabled rotation controls. The earlier
cropped capture and disabled-button foreground failure remain retained. Bootstrap's
disabled hit testing now has actual runtime evidence. Enrollment, rotation and
relay recovery remain separate acceptance work.

## Combined installed-device acceptance

The installed publication-conflict case passed the
[PR #205 combination](../../../deploy/validation-native-trust-conflict.md).
It prepares and verifies an independent authority backup through the
protected CLI, then publishes an old/new overlap with the normal compare-and-swap
operation while the original relay leaf remains active. A real native page
action against a scoped unavailable rotation endpoint must retain a prepared
journal without a server commit. The scheduled trust action must leave that
journal, model and application receipt unchanged. A verified old-credential
request must receive the exact trust-conflict 409; the native page must discard
only that uncommitted operation. Normal trust synchronization and a fresh page
rotation must then produce one distinct committed operation and audit, retain
identity/grants/GUI policy and recover the original verified route. A second
protected publication restores the original authority only after every active
fixture device has confirmed the overlap through the real API. The native router
uses its actual scheduled action; the stopped reference model persists and
independently verifies its roots, while the live witness deliberately reloads its
trust pool and proves new control plus its original TLS route before reporting.
Original witness control is checked before those planned trust reloads and a new
baseline is retained afterward. The original trust is then synchronized again.
Failures retain a fixed phase and go to owned stack teardown; an invalid cleanup
retirement must not mask the first error. The later authority tail accepts this
history only with the genuine native restoration receipt and original authority;
ordinary Compose still requires fresh history. Normal Remove and full cleanup
remain required. This does not establish an authority switch, durable off-host
custody, later-publication committed replay or public-network acceptance.

The first complete attempt at `fd7aa24` failed with a generic protected-publication
error before completing this case. Its exact logs, page outcomes and owned
cleanup are retained. The fixture's unconditional retirement could mask an
earlier failure and did not arrange the required reference confirmations. The
corrected flow preserves the first failure and records a fixed phase. Source
`cb7ae89` subsequently passed installed run `42001855424`, including the
shared-token/recovery/Remove/full-tail combination and eleven reviewed hashes.
Later failures and checker corrections remain documented in that record.

The committed-replay extension passed the separate
[PR #212 installed run](../../../deploy/validation-native-trust-conflict.md#committed-replay-after-a-later-publication),
including thirteen reviewed image hashes, both earlier interruption cases,
shared-token recovery, isolated restoration, Remove and the complete tail.
After every active device has genuinely confirmed overlap, a native page request
commits one candidate while the edge discards its response. The prepared journal
and original native model must remain. Normal guarded publication then retires
the unused successor root. Authenticated settings must expose that changed head,
while candidate replay returns the exact original assignment and older bundle.
The previous credential must receive HTTP 401; history, audit, credential hash,
claim timestamp and the retained journal must not change during the API probes.
The genuine native page must recover the same candidate, remove its journal and
then confirm current trust and verified TLS. A post-completion cron update is
allowed only when it exactly matches the independently delivered current head.
No cron/package edits or synthetic application rows bypass the scenario. Its
separate closed outcome and two page images are required along with the existing
publication/shared-token/restoration/Remove/full-tail evidence; source controls
alone do not accept this extension.

`native-enrolled.yml` waits for a successful six-job CI run for its exact PR source
before allocating a fresh guest. A separate image-gate job bounds that wait;
the existing CI deadline remains unchanged. Manual dispatch can also name the
exact-source producer. `with_images.py` verifies the producer, every required job,
artifact lifetime/checksum, image IDs and layers before loading the existing
tested images. It reuses `server/tests/compose.sh`; ordinary CI does not start a
guest. The optional native hook exercises the actual enrollment and rotation
page actions, configd, PHP model readback and verified assigned-route TLS.

The disposable guest imports only the fixture's public console CA through native
configuration/trust handling. A public CSR uses its existing GUI private key;
that key stays inside the guest. An owned test CA signs the CSR, and a fixture
helper applies the certificate and exact Alternate Hostname through Core Config.
Both native GUI security checks must remain enabled. This precondition is not
acceptance of production certificate issuance. Direct private management browser
TLS exceptions do not count as relay TLS verification.

The fixture checks retained identity/source grants/GUI key, native credential and
claim replacement, old-credential HTTP refusal, a genuine official-frpc stale
Login refusal, and verified TLS recovery at the same assigned route. It also
keeps an independent enrolled official client alive and checks its original
control socket and verified TLS before/after the native rotation. Both installed interruption cases have scoped execution evidence below. Linux
relay and FreeBSD contracts remain separate evidence; the complete combined
workflow still requires a successful exact-source run.

Only closed outcomes and selected native page images are made readable to the
artifact uploader. Tokens, snapshots, CSRs, fixture keys, raw child output and
service logs stay in root-only ephemeral storage. The runner discards them after
the test. No existing workstation VM, relay, production configuration or formal
package is used.

The first combined run at `02b2313` passed its image gate and installed the native
package, then failed during fixture system-trust preparation before enrollment.
Its owned guest exited with status zero and image cleanup passed. The helper now
uses `toArray(listtags())` to retain the legacy list representation required by
native trust handling ([native configuration adapter](https://raw.githubusercontent.com/opnsense/core/master/src/etc/inc/config.inc)).
Closed fixture-phase diagnostics retain the next failure location without private
exception text. This correction still needs an actual successful combined run;
the earlier failed result remains retained.

The next combined run at `3b9b38a` failed at the fixture's PHP host boundary,
before CA import. Root identity now uses FreeBSD's base `id` command instead of
assuming the optional PHP POSIX extension. The helper still requires one CLI
argument, FreeBSD and effective UID zero; the caller explicitly enables CLI
argument registration. A closed boolean runtime-condition receipt distinguishes
these prerequisites on the actual guest. Run `40798049843` at `548571f` confirmed
all host prerequisites and the absence of the POSIX extension, then failed during
native trust-store regeneration before enrollment. Exact source, both official
logs, closed runtime conditions and owned cleanup were independently retained.
The helper now loads `util.inc` and `legacy_bindings.inc`, checks required native
functions and respects deliberately suppressed native warnings. Unsuppressed
failures still stop the fixture. A bounded context can expose only an allowlisted
error class, source category and line number, never exception text or full paths.
These corrections still need a successful actual run; no installed rotation is
accepted from the failed trust preparation.

Combined `40801553085` at `340b73c` completed the native trust helper, then failed
in the guest's verified console probe before enrollment. Its old probe did not
classify the DNS/TCP/TLS/HTTP failure. The original fixture also used the host's
random forwarding port in its console URL, which conflicts with the existing
canonical Host check. The server still rejects that host/port combination.
The guest now uses `https://console.example.com` and virtual TCP forwards for
443 and 7000 to the owned host's loopback services. Per-connection
[QEMU guest forwarding](https://www.qemu.org/docs/master/system/invocation.html)
uses netcat as a byte pipe; TLS still terminates and verifies at the actual
console/relay. No server Host, Origin or TLS rule is relaxed. A closed probe
records DNS, TCP, default-system-TLS and HTTP categories without peer names,
paths or exception text. This correction requires another actual run; the prior
probe's exact failure type is not retrospectively established by source review.

Combined `40805730620` at `2db02e2` subsequently passed canonical console HTTPS
with the guest's default system CA directory and returned HTTP 200. Its actual
native enrollment page action passed, with the cleared token field and image
hash checked. The run then failed in the native backend read before rotation;
the original model failure class and lock mode were not exported. Overall
installed rotation remains unaccepted, and both official logs and cleanup were
retained.

One concrete initialization defect is corrected: FreeBSD
[`lockf` creates its file with mode 0666](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/usr.bin/lockf/lockf.c)
subject to the caller's umask. Package reconciliation previously did not set a
private umask before its first lock. The package now does so after restarting
configd; normal agent actions tighten an existing empty, owned, single-link lock
to 0600 only after acquisition, without replacing its inode. Links, shared inodes
and unknown content are refused. A required real FreeBSD regression forces the
old 022 umask and checks mode and inode retention. The original failed guest's
mode is still unknown; this is a demonstrated initialization defect rather than
a retrospective claim about that failure.

Root model failures retain only closed phase/class/source-category/line metadata;
the agent and page keep their fixed error responses. The hosted read probe still
calls the real native backend, exporting only that closed metadata on failure.
An earlier boolean storage receipt records actual lock/directory prerequisites.
No private node values or raw exception messages enter uploaded diagnostics.

Combined source `1c179ba` (`40812204828`) subsequently passed native enrollment,
Rotate, model readback, same-route verified TLS and retained GUI key/security
checks. Its two native page images were independently hashed and reviewed. All
twelve installed storage conditions passed. The run then failed at the required
old-claim Login evidence check, before both interruption cases. The old client
exited nonzero, but that alone does not prove authorization refusal. Authz logs
its decisions to stderr; the collector had read only Docker's stdout. It now
explicitly combines both streams, with actual subprocess regressions for stderr
events and fixed failure diagnostics. The original exact Login decision remains
unknown. Exact source, both official logs and owned cleanup are retained; this
partial positive path does not accept the complete installed workflow.

Combined `271f2a3` (`40814962539`) then passed the actual stale official-client
Login denial and old HTTP credential refusal. Response interception committed
exactly one operation/audit while retaining the same prepared candidate and
unchanged native model. The subsequent recovery page failed before completion;
the original internal error was not exported. Three successful page images and
hashes, exact source, both logs and owned cleanup were checked.

A concrete recovery defect is corrected: canonical journal JSON sorts native
snapshot keys. PHP previously required insertion order and compared native arrays
strictly. Validation now enforces the same exact field set and normalizes its
order before CAS/readback. A mandatory actual PHP case exercises both the initial
save and its idempotent retry from journal-order snapshots; missing/extra fields
and identity/policy changes remain refused. A failed-page probe reads only
journal phase and model-match booleans; it performs no HTTP retry or native save.
Successful installed recovery still requires actual execution.
The first FreeBSD run of this correction executed 214 cases with zero nonpassing
cases, but its required-case receipt failed: the older summarizer removed all
parameter labels, including the now-required `[journal]` identity. The summarizer
now preserves only explicitly allowlisted full identities; other parameter data
stays excluded. Missing, skipped, failed or alternate variants cannot receive the
required credit. The failed receipt remains retained and the revised driver still
requires actual hosted acceptance.


The additional unknown-commit fixture loses both real rotation responses after
the upstream returns, using the owned edge's
[response interception](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#intercepting-responses)
and [abort handler](https://caddyserver.com/docs/caddyfile/directives/abort).
It keeps console HTTPS unchanged and restores the original edge configuration
in `finally`. A failed page action must leave the original native model and a
prepared journal while exactly one candidate-bound operation/audit is committed.
The same page action then retries that retained operation, removes the completed
journal and restores verified TLS without changing identity, source grants or
the independent original control. Its actual recovery passed at source `1779316`, as recorded below.

A second owned helper waits for the real prepared journal, then holds the native
Core Config lock beyond the existing PHP save timeout. It never saves configuration
and has an external deadline. The fixture requires acknowledged lock ownership,
a received assignment, unchanged native model and one committed operation/audit.
After releasing the lock, the page must recover with the rotation endpoint serving
503, apply that same candidate, remove its journal and recover verified TLS.
The original edge configuration is restored in `finally`. A missed lock race
fails the fixture. Both interruption cases passed actual hosted execution at
source `1779316`; source and unit tests alone do not establish installed recovery.


Source `1779316` in [combined run 40818621704](https://github.com/KazuhaHub/nethub/actions/runs/40818621704)
passed its inner native result, including original-claim Login denial, old HTTP
credential refusal and both interrupted recoveries. Initial rotation recovered
verified route TLS in 3.053 seconds; response-loss retry took 3.104 seconds and
received-assignment retry with verified endpoint 503 took 3.522 seconds. Identity,
grants, GUI key/checks/alias, one-operation/audit replay and the independent original
control/TLS survived. Exact source, both official logs, six image hashes/visuals,
guest exit zero and owned image cleanup were reviewed. The outer Compose result
failed after native completion; its exact stage was not exported. This is scoped
native evidence, not a successful complete combined job.

The next fixture removes its extra enrolled device through the actual Remove
enrollment page before later authority transitions. It requires database revocation,
empty native credentials, disabled/stopped service, absent journal, closed assigned
route and the independent device still alive. Fixed post-native phase names are
recorded in a bounded `compose-tail.json`; child output stays private. Overall
success requires a completed tail as well as the native result. These new cleanup
and phase checks subsequently passed the complete installed records linked above.

The shared-token incident extension invokes the actual host CLI after native
enrollment. Its host fixture interrupts the process at a durable reload decision,
then requires the same candidate and bound services to recover through resume.
The genuine native Rotate page must obtain a different shared token using its
stored device bearer, retain all other model policy and GUI key/checks/alias,
and recover the same assigned route over verified TLS. An independent official
client also rotates and recovers; retained reference assignments are refreshed
for the later authority tests. A separate page image and bounded incident result
are retained. These cases passed the shared-token installed record linked above;
source and negative evidence-validator tests alone do not establish native recovery.

Serial bootstrap sends short encoded heredoc lines within FreeBSD's canonical
terminal input bound. Failure results retain only the waiting stage, selected
prompt flags, byte count and image-verification receipt; raw transcripts remain
private. A serial timeout does not establish that the package was installed.

An unexpected native page failure also requests a read-only FreeBSD descriptor
snapshot before the existing model probe. The snapshot uses the documented
[`procstat` file view](https://man.freebsd.org/cgi/man.cgi?query=procstat&sektion=1&manpath=FreeBSD+15.1-RELEASE)
to select held descriptors for the exact mutation lock. Up to four matching
processes are classified into fixed agent/wrapper roles. Raw paths, process IDs,
arguments and utility diagnostics are not exported. Collection has one eight-second
budget, bounded reads and fixed unavailable/timeout/malformed outcomes. The upload
contract includes only its validated projection.

This is a snapshot after the failed action, not an atomic record of that action's
lock owner. A holder may exit or change before observation; an empty snapshot does
not disprove earlier contention. Probe failure preserves the original page failure.
The fixture does not replay Rotate, modify the scheduler or convert a failed
installation run into acceptance.

The fixed lock snapshot and rotation-condition read share the same four-event
read-only SSH recovery budget as model/GUI inspection. They use already staged
helpers and never replay the failed action. The Rotate API classifies additional
exact local error messages into closed request, binding, runtime, service and
timeout categories; unknown messages still remain unclassified and private.

A failed first post-Rotate route check retains its last existing curl status and
one read-only native snapshot in `installed-route-failure.json`. The snapshot
compares the live claim/token with the native model, records service and local
stop state, and exports only fixed reconciliation actions and recognized log
events. It exports no credential, endpoint, arbitrary log line or child error.
The probe does not retry SSH, replay Rotate, restart frpc or extend the route
budget. A missing or malformed snapshot remains diagnostic failure; the original
route failure still fails the run. A later snapshot cannot prove the state at the
instant of the failed route request.

Pinned upstream sources:

- [OPNsense 26.7 announcement and image checksums](https://raw.githubusercontent.com/opnsense/changelog/fd539a8f722f56354e117faa5ab1495a4ad14d5b/community/26.7/26.7)
- [Go release archive checksums](https://go.dev/dl/?mode=json&include=all)
- [OPNsense factory interface assignments](https://docs.opnsense.org/manual/interfaces.html)
- [FreeBSD canonical terminal limits](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/sys/sys/syslimits.h)
