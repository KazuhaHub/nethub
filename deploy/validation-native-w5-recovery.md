# Native recovery diagnostic

The guarded 0.0.17 experiment completed actual WAN-address and guest-reboot
checks, then failed configuration-restoration recovery. The failed operation is
retained as failed; it does not complete the combined W5 recovery requirement.
The approved 1 GiB allocation remains a resource deviation.

| Native observation | Result |
| --- | --- |
| WAN address changed on the owned WAN adapter | Same frpc PID logged in and restored its proxy; the new source address was observed in sockstat |
| Changed WAN to verified public GUI | 23.552 seconds to successful observation |
| Original WAN restored | Original address and system-trusted public GUI recovered |
| One guest reboot | SSH became unavailable and the kernel boot epoch changed |
| Reboot dispatch to verified public GUI | 125.063 seconds to successful observation |
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
Installed 0.0.18 restoration acceptance is still pending.

Failure cleanup genuinely revoked the created fixture, closed the issuer and
relay window, restored the original cold checkpoint and verified the original
package, configuration and stopped intent. All fourteen original server containers
and listener owners were restored. Normal GUI removal was not completed in this
failed operation. Operational addresses, backup XML, credentials, certificate
material and raw logs remain outside Git.

Native heartbeat cutoff, console Revoke/no reconnect and the W5 mobile Open sample
remain separate requirements. W5-W7 are incomplete.
