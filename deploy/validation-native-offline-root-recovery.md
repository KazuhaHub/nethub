# Native offline root rotation and recovery

The unsigned 0.0.16 package passed an actual relay authority switch and old-root
retirement while the enrolled appliance was powered off. After boot, genuine
package cron confirmed the successor-only trust generation without manual sync.
Native UI removal and independent restoration checks also passed.

## Inputs and scope

- OPNsense 26.7.7 / FreeBSD 15, with the owner's accepted static 1 GiB exception.
- Package source `0ed94ed`, accepted in [PR #146](https://github.com/KazuhaHub/nethub/pull/146)
  after six successful jobs in run 40057559906, actual log checks and DCO.
- Separate owned relay deployment, retained PostgreSQL history, official frp
  0.71.1 clients/server and independently backed-up successor authority material.
- Private CA and explicit lab DNS. The console fixture root was persisted using
  the native trust mechanism; an explicit lab hook restored its DNS entry at boot.
- Independent native and relay deadline guards. The tested package was exported
  and inspected before installation; no signed release was produced.

Issuer key separation retains the accepted deployment boundary documented in
the [secret isolation evidence](validation-enrollment-boundaries.md). This
rotation used the same application definitions and component identities.

The deployment initially retained three revoked fixture devices. No database or
trust generation was reset to create a clean-looking result. The new enrollment
used the actual console and native browser flow.

## Observed sequence

| Step | Independent evidence |
| --- | --- |
| Browser enrollment | HTTP 200, assignment saved, tunnel ready and console online in 8.248 s without reload or manual refresh |
| Initial trust | Genuine cron confirmed generation 5; native model, CA file, journal and authenticated receipt agreed |
| Overlap | Genuine cron confirmed generation 6 containing both roots before the appliance went offline |
| Shutdown | The same owned appliance was Off before activation; nine Off samples covered the recorded 32.545 s interval, with every sampling gap below 5 s |
| Authority switch | Protected production commands committed the prepared successor while the appliance remained Off, verified the served leaf and rejected old-only client trust |
| Retirement | Generation 7 contained only the successor root; exact resume retained the committed receipt |
| Early boot | A changed boot identity, the same device/key and persisted generation-6 trust were observed before synchronization |
| Recovery | Genuine package cron confirmed generation 7, with matching native/SQL state and two stable tunnel PID samples; dispatch to confirmed observation was at most 234.545 s, including boot and polling |
| Public route | A bounded GUI request passed through the relay and matched the original native leaf pin |
| Removal | Actual native UI removal completed; a fresh console login showed Revoked and the former subdomain could no longer complete TLS |
| Restoration | Original native configuration, package 0.0.6, stopped intent, stock GUI script, managed trust and all fourteen original relay services/listener owners were independently checked |

The database capture contains exactly one immutable application for each of
generations 5, 6 and 7 for this device, plus the corresponding authenticated audit
events and committed authority operation. No acknowledgement was fabricated.
The device secret and GUI private key remained identical across the exported
native profiles; neither is included in this report.

## Verification

The off-host verifier checked the successor backup's bytes, modes and numeric
ownership; CA and leaf signatures; served identity; SQL generations, applications
and audit bindings; native model/file/journal agreement; boot and sampled host
state; and removal/restoration receipts. It also bound the nineteen executed
coordinator/helper inputs and the exact tested package.

Root fingerprints were independently derived from the persisted native PEM and
compared with PostgreSQL and the retained authority backup. Native model metadata
intentionally omits the server's root array. The first verifier's incorrect
schema assumption and its failure were retained before correcting this check;
the same immutable runtime capture then passed the complete verifier.

Both startup memory checks retained the existing minimum reserve. Optional
reclamation affected only verified ancestors of the current task; no unrelated
application was closed and the VM allocation was unchanged.

Earlier initialization, host-start binding/reserve and pre-key enrollment
failures remain failed records. The unsigned build's final log-name collision
was also retained; separate readiness/baseline checks completed its closure
without rebuilding or rewriting the original failure.

## Limits

This exercises ordinary rotation after the active device acknowledged overlap.
It does not establish emergency recovery for a device that never received the
successor root. The GUI route used a leaf pin; it was not a public CA/name
validation. Public CA acceptance, combined W4 certificate acceptance and W5-W7
remain incomplete. The measured boot/recovery time is specific to the 1 GiB lab
and is not a production recovery promise.
