# Native authority transition and trust-job deadline fix

On 2026-10-22, a genuine OPNsense client survived the protected relay CA switch.
The original root was then retired from the published trust bundle. A controlled
recovery exposed a process-deadline defect: trust was installed and confirmed,
but the outer command later stopped the new tunnel. Unsigned package 0.0.13
passed both manual and scheduled recovery, with the tunnel remaining online
beyond that deadline.

See the [sanitized receipts](validation-relay-authority-native.json) and preceding
[admission/recovery record](validation-relay-trust-recovery.md). Private inputs,
assignments, operation identities, signing material and raw logs remain outside Git.
This measurement does not complete W4.

## Failed lab enrollment and backup

The earlier aborted enrollment lacked retained returned credentials and had no
application report. It previously blocked actual activation. Before explicitly
retiring it, a custom PostgreSQL dump was copied off the relay, flushed, reread
and hashed. All 24 public tables restored with matching contents and counts in
a separate database, including device, application and audit history.

The administrative update was rehearsed on that copy. Its initial audit call
refused schema access because the copy had the wrong database owner; the
transaction rolled back. Matching the original owner restored the intended
schema authority. The completed rehearsal preserved prior audit entries,
appended one system event and passed independent audit hash-chain validation.
The source database stayed unchanged throughout rehearsal.

The original lab then received the same scoped administrative action. All three
device records and four genuine application records were retained. The two
recoverable identities stayed active. Only the failed identity's revocation,
timestamp, last-seen and disabled-state fields changed. One system audit event
recorded the reason and backup/rehearsal references; other tables and earlier
audit entries were unchanged. This is explicit lab administration, not product
revocation acceptance or an exception to all-active-device admission.

## Actual signer switch and root retirement

Both active identities had genuine generation-2 applications before admission.
The online native client used both roots. The host command verified candidate
backup/custody, obtained a healthy service fingerprint and retained its complete
original input. Activation committed the file journal and SQL switch decision;
explicit resume returned the same terminal receipt.

Fresh TLS verified the successor leaf and hostname under the successor CA.
A client trusting only the original CA rejected that successor server certificate.
frps reported the native HTTPS proxy online. The bound from command dispatch
to that proxy observation was 16.810 seconds, including command and checks;
it is not an outage duration or SLO. Native PID/CA bytes, unrelated service IDs,
credentials, application rows and audit history were unchanged across the switch.

The protected publication command then advanced generation 2 to generation 3,
containing only the successor root. It checked both active predecessor
applications. Publication left runtime/authority files, service IDs and earlier
application history unchanged.

## Reproduced deadline defect and fix

With only the package scheduler isolated, an exported generation-1 native model
refused fresh control TLS under its stale root. Its actual configd trust action
installed and confirmed generation 3, but the client waited until the outer
deadline. The new frpc PID file disappeared afterward. This failed trial is
retained separately; it is not a passing recovery.

FreeBSD's default timeout reaper waits for daemon descendants after its command
exits and signals them at expiry. This was reproduced independently on the
appliance; see the [FreeBSD 15.1 implementation](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/bin/timeout/timeout.c).
The new trust-job runner releases daemon descendants when the direct command
finishes. Timeout or cancellation still terminates its owned process tree with
bounded TERM/KILL escalation, including detached children that ignore TERM.
The shared lock and agent's internal deadline remain in place.

Five actual FreeBSD cases passed: the stock regression control, normal daemon
handoff, recursive deadline cleanup, cancellation and exit status. Hosted Linux
passed 710 plugin cases with 13 skips: eight existing skips and these five native
cases, which ran separately without skips against matching source/test hashes.

## Corrected native recovery

The rebuilt 0.0.13 package was installed and checksum verified in each fresh
appliance window. Its manifest, product and model versions matched, and its
runner bytes matched the tested source. No new enrollment or acknowledgement
was fabricated. Each replay restored the older genuine model through PHP.

| Caller | Observed behavior |
| --- | --- |
| Manual configd | Package cron was paused and drained under the shared lock. Stale-root TLS refused; the action installed one successor root and confirmed generation 3 in 2.773s. A repeat completed in 1.265s with unchanged PID/CA. Fresh successor TLS passed. |
| Package cron | The original packaged scheduler stayed in place. New log output after a recorded inode/offset confirmed generation 3; no manual trust action was invoked. Model and installed CA matched the publication. |
| Beyond the old deadline | Manual and scheduled replays retained their PID/CA for 115.172s and 116.390s of subsequent observation. frps reported the HTTPS proxy online afterward. |

The first failed trial had already created a genuine backend generation-3
application. Both corrected replays retained its first acceptance timestamp,
one application and one audit record; they did not create a new receipt.
The other active identity retained its generation-2 application.

Owned logs and native state were exported before independent restoration.
Checks confirmed the original fourteen running containers and 443/8443
owners/configurations, stopped test services and retained database/new authority.
The appliance returned to its exact original configuration, 0.0.6 package,
stopped intent and cold checkpoint.

## Inputs and remaining acceptance

The fixed native source is `79ea01ee3a7cd3c4bfdd979fc99fc41b984bbe50`. Its unsigned package
SHA256 is `a23dd037b3565e98d567e447f7e9480baf205d50fc87171b3f67ec7893a3e7ce`. All six source checks passed in
[run 39868811152](https://github.com/KazuhaHub/nethub/actions/runs/39868811152).
The preceding signer switch used accepted 0.0.12 inputs; corrected recovery used
0.0.13. Server images remained the accepted deployment inputs. Both peers used
frp 0.71.1 built with Go 1.26.10.

The owner-approved 1 GiB appliance deviation and 4 GiB Linux LXC remain. Console
HTTPS used an independent private fixture CA with hostname verification. Genuine
identities were replayed sequentially on one appliance; this is not a test of
simultaneous physical routers, capacity or latency SLOs.

The original initial-sync timeout is not retroactively accepted. This test
establishes controlled local generation-1-to-3 recovery through corrected callers.
Fresh browser enrollment/initial synchronization and the complete native GUI
certificate issuance/install/renewal path remain to be validated. No public CA
account/order, formal release custody, physical host power-loss result or W5-W7
completion is claimed.
