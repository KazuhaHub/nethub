# Native recovery diagnostic

The guarded 0.0.17 experiment completed actual WAN-address and guest-reboot
checks, then failed configuration-restoration recovery. The failed operation is
retained as failed; it does not complete the combined W5 recovery requirement.
The approved 1 GiB allocation remains a resource deviation.

| Native observation                                             | Result                                                                                          |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| WAN address changed on the owned WAN adapter                   | Same frpc PID logged in and restored its proxy; the new source address was observed in sockstat |
| Changed WAN to observed frpc login/proxy and new socket source | 23.552 seconds; the subsequent system-trusted public GUI probe passed                           |
| Original WAN restored                                          | Original address and system-trusted public GUI recovered                                        |
| One guest reboot                                               | SSH became unavailable and the kernel boot epoch changed                                        |
| Reboot dispatch to verified public GUI                         | 125.469 seconds to successful observation                                                       |
| Identity after reboot                                          | Device configuration, GUI private key and installed version retained                            |
| Native backup and restore                                      | Actual GUI download and Core restore accepted; enabled intent restored                          |
| Automatic service recovery after restore                       | Failed: frpc remained stopped at the 90-second deadline                                         |

The public probes checked the exact issued leaf, hostname and system trust. The
WAN and reboot helpers did not manually start or reconcile the agent. A real
console Open and authenticated public GUI check preceded those measurements.
The reboot measurement includes dispatch and polling overhead.

The restore test first saved a native backup, saved disabled intent through the
plugin Settings API, and observed normal cron stop the service. It then uploaded
the backup through OPNsense's native configuration page, without requesting a
reboot or replacing config.xml directly. Enabled intent returned to `1`, but a
watchdog tick ran before normal reconcile restarted the service. The watchdog
treated the intentional stop as a crash, rejected a last-good configuration bound
to earlier trust and quarantined the otherwise unchanged desired configuration.

The 0.0.18 development fix makes the independent watchdog wait for reconcile when
the plugin's rc flag explicitly remains disabled. Reconcile validates the restored
intent before enabling and starting the service. This wait neither clears an
existing quarantine nor spends its one-attempt recovery budget. Actual crashes
with an enabled rc flag retain the existing rollback and trust checks.

A temporary source-only regression on the real FreeBSD appliance reproduced
`last_good_trust_mismatch` before the fix: one failed, 35 passed. After the fix,
all 37 related reconcile, managed-trust and watchdog tests passed, including
preservation of an existing quarantine. These tests did not install the candidate
or alter the native configuration; the installed version remained 0.0.6.
At that checkpoint, installed 0.0.18 restoration acceptance was still pending.

Failure cleanup genuinely revoked the created fixture, closed the issuer and
relay window, restored the original cold checkpoint and verified the original
package, configuration and stopped intent. All fourteen original server containers
and listener owners were restored. Normal GUI removal was not completed in this
failed operation. Operational addresses, backup XML, credentials, certificate
material and raw logs remain outside Git.

## Installed 0.0.18 recovery checks

PR #164 merged as `15f58cb` after six exact-head checks in run `40168316763`,
actual log inspection and four signed commits. The unsigned FreeBSD build used
source `db862f9`, took 331.498 seconds and matched all 46 tracked packaged source
files. Package, product and native model versions agreed. Independent checks
verified the original appliance baseline after the build.

A fresh guarded operation installed that package and completed all three native
recovery checks. Public TLS used normal DNS and system trust, with the exact issued
leaf checked. A fresh authenticated GUI browser passed after all three recoveries.

| Measurement                                                |  Observed |
| ---------------------------------------------------------- | --------: |
| Enrollment click to automatic online display               |   7.572 s |
| GUI certificate issuance to native confirmation            |   2.683 s |
| WAN change to observed login/proxy and new socket source   |  26.360 s |
| Guest reboot dispatch to verified public GUI               | 128.500 s |
| Native Core restore acknowledgement to verified public TLS |  45.578 s |

The WAN check retained the frpc PID and restored the original address afterward.
The reboot changed the kernel boot epoch and preserved device identity and the GUI
private key. The actual Core backup/restore returned enabled intent to `1`; normal
cron restarted the service without manual agent start or reconcile. The restore
itself did not reboot the guest. The approved 1 GiB deviation remains.

The overall operation remains **failed** because its subsequent normal GUI removal
returned HTTP 200 with `success=false` and the message that removal was unconfirmed.
That request overlapped the normal report schedule; its exact failure cause remains
unconfirmed. That trial did not verify a removal retry. The three preceding recovery
results and fresh public login passed independent checks without changing that
failed overall outcome.

Fallback cleanup genuinely revoked the created device. Separate read-only database
inspection verified revocation, a valid issued order, retired proof and unchanged
generation/application history for all three retained devices. Its independent
database stop guard closed. Original native configuration, trust, restart script,
package and stopped intent, plus all fourteen original server services and listener
owners, were restored and independently checked. No normal UI cleanup or final
removed-route observation is claimed for this operation.

## Removal retry with an already revoked profile

A separate guarded test reinstalled the same unsigned 0.0.18 package and restored
the preceding device's actual Core backup and exported owned files. The device
remained revoked throughout. No enrollment, GUI certificate order or reactivation
was performed. The restored GUI passed chain, hostname and exact-leaf checks.

An independently bounded process held the actual shared reconcile lock. Native
`lockf` returned 75, and the real Remove enrollment button returned the same
unconfirmed response. The complete native XML and GUI key hashes remained unchanged.
After the lock was released, one explicit click of the same button succeeded:
the native model was cleared, runtime credentials and the plugin's GUI key file
were removed, and the interface reported cleanup complete.

A fresh console login rendered the retained device Revoked. Its old subdomain
could not complete TLS while the public TCP listener remained reachable. All three
revoked device records, tokens and certificate request/job/generation/application
records matched their before-test values. Independent checks verified source
bindings, native configuration/trust/restart restoration and all fourteen original
server services. The approved 1 GiB deviation remains.

This reproduces shared-lock contention as a retry condition; it does not establish
the exact cause of the earlier unconfirmed request. The earlier recovery operation
remains failed. Two additional harness trials are retained: a duplicate step-log
failure after the first refusal, and a storage preflight refusal before stack
startup. Their guarded baselines were restored before the successful retry test.
The test does not measure live console revocation or heartbeat cutoff.

The subsequent [heartbeat and console Revoke record](validation-native-w5-heartbeat.md)
contains actual cutoff and no-reconnect measurements. Its W0 timing comparison
and the W5 mobile Open sample remain open. The failed combined recovery operation
above remains failed; W5-W7 are incomplete.

## New-heartbeat hosted WAN candidate

The hosted acceptance candidate changes the fixed WAN address of its disposable
OPNsense guest, using independent LAN SSH. A root-owned nonce, expected native
LAN/WAN assignments, the fixed private subnet and gateway bind the operation to
that guest. It checks the original frpc PID/start time and the actual established
control socket's new source address, then verifies the existing HTTPS route.
Socket state and process ownership are read through the stock
[FreeBSD sockstat interface](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/14.3/usr.bin/sockstat/sockstat.1).
The unrelated witness must retain its original TCP inode and verified route.

The harness restores the original address even if the change response is lost.
Both changes have a separate 60-second recovery limit; this does not extend the
five-second revocation target. A late observation or partially recovered trial
stays failed. No manual agent start, restart, reconcile or grant renewal is used.
The native model, runtime configuration, native XML, GUI identity and database
identity/grants must remain unchanged.

The original candidate `d6f1b43` failed at the change phase in
[installed run 43371274201](https://github.com/KazuhaHub/nethub/actions/runs/43371274201).
Restoration was attempted but not verified. The retained outcome did not identify
the failing operation; it cannot establish whether the default route disappeared.
Keep that trial failed. Review separately found that the fixture replaced the
primary address without restoring a dependent default route. The follow-up checks
the IPv4 route table and reinstates only the absent fixed fixture gateway after
each address change, within the original recovery clock. An unexpected gateway,
interface, duplicate route or malformed table is refused, never overwritten.
Address configuration and default-router configuration are separate steps in the
[FreeBSD network handbook](https://docs.freebsd.org/en/books/handbook/network/).
Version-two outcomes retain closed failure reasons for the original operation and
restoration separately, without publishing child output. A successful restoration
does not turn the original failed operation into a passing trial.

The follow-up `1624ff9` passed CI, 217 actual FreeBSD cases, preparation and
isolated cold recovery, but its
[installed run 43377788624](https://github.com/KazuhaHub/nethub/actions/runs/43377788624)
failed in the relay prerequisite before starting a native guest. It did not
execute the WAN change and cannot validate or refute the gateway fix. The retained
projection identified only the broad relay phase; previous successful Go source
locations do not establish the later Python failure's cause. The diagnostic
follow-up adds fixed relay component phases and allowlisted Python traceback
locations and deadline hints without exporting child output or repeating a timed
action inside a failed run. It changes no cutoff limit, workload or recovery guard.

Source `d5c0d5f` executed that gateway fixture in
[installed run 43382960772](https://github.com/KazuhaHub/nethub/actions/runs/43382960772).
The version-two WAN outcome passed: the changed address recovered in 3,102 ms
and restoration in 4,053 ms. The original frpc process, native model, runtime
configuration, XML, GUI identity and independent control/TLS witness were retained.
These are WAN recovery measurements, separate from revocation timing.

That overall run remains failed. After the first normal Rotate succeeded, a
read-only native fixture inspection timed out connecting to SSH. The retained
transport category does not establish whether the private listener stopped or
the connection failed transiently. No later full-tail acceptance is inferred.
The follow-up allows only that fixed inspection to recover the disposable CI
guest's original private SSH listener and repeat the same read once. It retains
the initial transport category, listener recovery status and elapsed recovery
time, with a four-event budget for the entire guest. Host-key, authentication
and command failures remain fatal; Rotate, Revoke and other mutations are never
replayed. The original failed run is preserved.

The next source `2e76868` passed CI, native filesystem checks, preparation and
isolated cold recovery, but
[installed run 43391262433](https://github.com/KazuhaHub/nethub/actions/runs/43391262433)
failed at private input transfer after its first successful Rotate. Its standalone
WAN change and restoration passed in 2,925 and 4,542 ms. Its read-only recovery
inventory was empty: the failure preceded the recovery helper. SCP's retained
error did not distinguish a transport problem from another transfer failure.
Both the model readback and GUI inspection had a preceding upload, so the exact
failed upload and daemon cause remain unconfirmed.

The follow-up reuses the model probe staged before enrollment instead of uploading
it again for every read. Model readback uses the same bounded, fixed-command
recovery boundary. A pinned read-only root probe checks that boundary before
staging GUI inspection input. Closed recovery records distinguish those three
read-only operations. SCP failures retain private child logs and export only an
allowlisted category; SCP and mutations are not retried. Host-key and authentication
refusals take priority over accompanying reset messages, and child stdout cannot
claim an SSH transport failure. These fixture changes need their own hosted
execution; neither failed run becomes accepted.

Source `c0ff774` passed CI, native filesystem checks, preparation and isolated
cold recovery. Its
[installed run 43398908870](https://github.com/KazuhaHub/nethub/actions/runs/43398908870)
remains failed. The first ordinary Rotate succeeded. Its subsequent model-read
SSH connect timeout recovered through the fixed read-only boundary in 10,580 ms;
the read completed and native credential/assignment and database-preservation
checks passed. The assigned route then failed to recover verified TLS within
the existing probe budget.
Its WAN change/restoration passed in 2,980/4,536 ms. Those observations do not
establish why the route failed, and the run never reached console revocation.

The follow-up retains the last existing curl outcome and one read-only native
snapshot on that route failure: service/stop state, live-versus-model credential
equality, fixed reconciliation action and recognized log events. It adds no
route retry, configuration change or longer budget. Arbitrary errors, logs and
credential values stay out of uploaded evidence. Local projection checks do not
establish installed recovery; a new original execution is required.

This is a runtime address change behind the fixture's NAT, not a public-network
or ISP DHCP-renewal sample. Local parser/orchestrator tests do not establish
automatic recovery on an actual appliance. The candidate must execute with the
new one/three-second heartbeat settings, retain its closed outcome and pass the
later normal Remove/full-tail/cleanup checks before accepting that scope.
Reboot, Core restore, public/mobile, migration and rollback remain separate.
