# Native recovery diagnostic

The guarded 0.0.17 experiment completed actual WAN-address and guest-reboot
checks, then failed configuration-restoration recovery. The failed operation is
retained as failed; it does not complete the combined W5 recovery requirement.
The approved 1 GiB allocation remains a resource deviation.

| Native observation | Result |
| --- | --- |
| WAN address changed on the owned WAN adapter | Same frpc PID logged in and restored its proxy; the new source address was observed in sockstat |
| Changed WAN to observed frpc login/proxy and new socket source | 23.552 seconds; the subsequent system-trusted public GUI probe passed |
| Original WAN restored | Original address and system-trusted public GUI recovered |
| One guest reboot | SSH became unavailable and the kernel boot epoch changed |
| Reboot dispatch to verified public GUI | 125.469 seconds to successful observation |
| Identity after reboot | Device configuration, GUI private key and installed version retained |
| Native backup and restore | Actual GUI download and Core restore accepted; enabled intent restored |
| Automatic service recovery after restore | Failed: frpc remained stopped at the 90-second deadline |

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

| Measurement | Observed |
| --- | ---: |
| Enrollment click to automatic online display | 7.572 s |
| GUI certificate issuance to native confirmation | 2.683 s |
| WAN change to observed login/proxy and new socket source | 26.360 s |
| Guest reboot dispatch to verified public GUI | 128.500 s |
| Native Core restore acknowledgement to verified public TLS | 45.578 s |

The WAN check retained the frpc PID and restored the original address afterward.
The reboot changed the kernel boot epoch and preserved device identity and the GUI
private key. The actual Core backup/restore returned enabled intent to `1`; normal
cron restarted the service without manual agent start or reconcile. The restore
itself did not reboot the guest. The approved 1 GiB deviation remains.

The overall operation remains **failed** because its subsequent normal GUI removal
returned HTTP 200 with `success=false` and the message that removal was unconfirmed.
That request overlapped the normal report schedule; its exact failure cause remains
unconfirmed. Removal retry verification is open. The three preceding recovery
results and fresh public login passed independent checks without changing that
failed overall outcome.

Fallback cleanup genuinely revoked the created device. Separate read-only database
inspection verified revocation, a valid issued order, retired proof and unchanged
generation/application history for all three retained devices. Its independent
database stop guard closed. Original native configuration, trust, restart script,
package and stopped intent, plus all fourteen original server services and listener
owners, were restored and independently checked. No normal UI cleanup or final
removed-route observation is claimed for this operation.

Native heartbeat cutoff, console Revoke/no reconnect and the W5 mobile Open sample
remain separate requirements. W5-W7 are incomplete.
