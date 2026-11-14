# Five-second revocation target

Kazuha retained the five-second target on 2026-11-12 and authorized changes to
heartbeat and revocation processing. The original installed result, 17.218 seconds
from console confirmation dispatch, remains a failed timing comparison. Do not
replace it with an easier threshold or restart the clock at database commit.

## Scoped public console measurement, 2026-11-13

One normal public-console Revoke on the retained genuine OPNsense enrollment
disconnected its actual frps control and proxy within 788 ms. A fresh public TLS
connection was refused within 856 ms. Both measurements use the same Windows
monotonic clock, started before the normal CSRF-protected confirmation click.
The target did not reconnect during the following 30.113 seconds.

An independent reference client used ordinary enrollment, its own managed key,
a genuine production-CA certificate and normal console Open. Its original control
record, Linux process/start time and TCP socket inode survived the measurement.
Fifty-five fresh public nonce checks passed; browsers and Node used normal public
roots and hostname/leaf/key verification, without certificate exceptions. Only
management observations used a pinned SSH forward to the existing private bridge.

The tested deployment and unsigned 0.0.19 package were built from `d5c0d5f`, on the
approved local OPNsense 26.7.7/1 GiB environment. Before confirmation, its genuine
public GUI passed login, eleven widgets, recurring API calls and dashboard reload.
Two earlier preflight windows failed before any confirmation: one discarded an
unparseable start response; the other used a missing optional SSH configuration
field after the GUI passed. Both failures remain retained. The single timed
confirmation was not retried. Independent cleanup stopped the test clients before
restoring the original services; all sixty container/image identities and the
fifty-nine unaffected process states were verified. Private logs, six actual
views, their hashes and the executed harness hash remain outside Git.

This closes one desktop public IPv4 timing sample, not the complete W5 gate.
It does not establish mobile timing, termination of existing browser streams,
public renewal, mixed-version migration/rollback or the full latest-source
installed regression. Source `71742b6` passed CI, preparation, filesystem and cold
recovery, but its installed run
[43415757113](https://github.com/KazuhaHub/nethub/actions/runs/43415757113) failed
at fresh Rotate with `trust_sync`, before a pending rotation journal. Its lock
snapshot found no held descriptors; this does not establish the original cause.
The actual hosted WAN change/restoration checks passed in 4.092/4.609 seconds.
That failed run remains failed and did not reach its native Revoke measurement.

The follow-up retains only a closed stage/error-kind receipt when trust blocks
fresh rotation. This private record never includes exception text, backend output,
paths or credentials and is absent from the GUI/status response. Scheduled trust
does not overwrite it; normal Remove deletes it. The read-only failure probe
accepts only a bounded, canonical root-owned 0600 file and validates the projection
again before publishing an artifact. Recording failure does not retry HTTP,
recovery or native saves, and recording errors cannot replace the original failure.
FreeBSD source contracts now require actual private-file and agent-dispatch checks.
This adds diagnosis; the original `trust_sync` cause and full installed result
remain unproven until the new source executes.

Source `9ecc914` subsequently passed all six CI jobs, 239 actual FreeBSD cases,
package preparation and isolated cold recovery. Its installed run
[43426605115](https://github.com/KazuhaHub/nethub/actions/runs/43426605115) still
failed before the first rotation journal: the protected receipt identified
`request` / `protocol` in trust synchronization. This narrows the failing boundary
but does not distinguish connectivity, TLS or an HTTP/protocol rejection.
The follow-up classifies only known local exception types and the fixed local
rejection message into closed categories. It exports no child text, response
status/body or address and does not issue an additional request or retry Rotate.

Both public test enrollments were subsequently removed through their normal
authenticated paths, including the native Remove UI and runtime cleanup. Only
the original GUI certificate selection and alias text were restored; other XML
and certificate records were preserved. The unused managed test certificate and
protected evidence remain. The nonce-owned nonlogin reference user/group and
service were removed after verifying no remaining UID processes; its retained
state is root-only. Original services and container/process continuity passed.

The later `f08585d` installed run
[43549725046](https://github.com/KazuhaHub/nethub/actions/runs/43549725046) passed
normal enrollment and its first Rotate page, then failed staging a private test
input with `guest_ssh_connect_timeout`. Both actual views, exact archive/logs,
guest exit and cleanup were checked; the overall run remains failed and did not
reach its Revoke measurement. WAN change/restoration passed in 2.614/4.497 seconds
with original native/process/route invariants. No read-only inspection recovery
was recorded. These facts do not establish the cause of earlier `trust_sync`
failures.

The follow-up checks the existing fixed read-only root boundary before uploading
private test inputs, sharing the four-event inspection-recovery budget. It does
not retry a failed upload or replay Rotate/Revoke. Separate local source `f08585d`
[reboot and configuration-restore observations](../deploy/validation-native-w5-recovery.md#current-0019-local-recovery-sample)
retain their public-server-source and 1 GiB limits; no new current-source Revoke
timing is inferred from them.

## Development candidate

- Agent 0.0.19 sends a heartbeat every nominal second and uses a three-second
  timeout; generated relay configuration uses the same timeout. The unchanged
  pinned frp client includes heartbeat jitter and a separate one-second timeout
  check ([source](https://github.com/fatedier/frp/blob/v0.71.1/client/control.go)).
- Authz refreshes the memory denial set every second, with a shared one-second
  read budget for revocations and claim floors. Disconnect acknowledgements use
  an independent worker and cannot queue this refresh behind their database locks.
- A snapshot admits Ping for at most 2.5 seconds from the start of its read.
  Failed reads retain known denials but cannot keep admitting unrelated identities
  indefinitely. A stale/future-dated snapshot refuses Ping; the freshness
  self-check stops authz so its ordinary restart policy can recover.
- Known revocations and issuance floors remain monotonic. Ping still performs no
  SQL. Login, NewProxy and NewUserConn continue to validate current database state.

These changes increase heartbeat and snapshot-read load and can interrupt access
during shorter stalls. Timer values and unit tests do not prove the deadline.
Old agents and old generated bundles retain their old timing until upgraded;
changing only Web/authz does not establish the target for an existing fleet.
Keep an independent recovery path and reviewed configuration rollback material.

## Existing development deployments

First inventory and upgrade agents to the new rendered heartbeat configuration,
while retaining the existing relay timeout during that stage. Only lower the
server timeout after the participating agents are ready. The [server checks the
time since its last accepted Ping](https://github.com/fatedier/frp/blob/v0.71.1/server/control.go);
lowering its timeout while old clients retain a ten-second interval can repeatedly
disconnect those clients. Offline agents need an independent upgrade/recovery path.
An incomplete migration does not establish the five-second target for that fleet.

Then deploy the reviewed authz behavior and relay configuration, with the planned
relay restart and retained rollback material. Verify the new settings, repeated
cutoff samples and recovery on the actual devices. A rollback must restore a
compatible relay timeout before reverting agents to their old interval. Mixed
versions, short outages and rollback still require actual validation; this order
is an operational requirement, not a completed compatibility result.

## Required validation before acceptance

1. Preserve every original signature, tenant, peer, claim-floor and disconnect
   completion guard. Test concurrent publication, stalled/cooperative database
   failures, stale reads, cancellation and restart. Known denials must survive.
2. Measure snapshot completion and Ping throughput under bounded representative
   fleet sizes and near supported snapshot limits. Report CPU, latency and false
   disconnects; do not infer fleet capacity from an in-memory unit test.
3. Exercise real pinned frps/frpc at varied heartbeat/refresh phases. Retain every
   attempt, control-session loss, proxy state, existing-stream behavior, new TLS
   refusal, Ping/Login denials and unaffected-device recovery. Do not retry until
   a favorable phase passes. A direct SQL fixture is only a prerequisite.
4. Repeat normal console Revoke on the actual native agent. Record confirmation
   dispatch, HTTP response/commit, cache publication, Ping refusal, original
   control/proxy loss and verified fresh TLS refusal with clock/sample resolution.
   The acceptance clock starts at dispatch. Observe that the same revoked client
   cannot reconnect, including after service/agent recovery.
5. Repeat public/mobile availability and WAN-change recovery. Explicitly test
   backend outage and hangs, short network interruptions, configured timeout
   behavior and operator recovery. Report limitations and all failed cases.

The ordinary relay fixture now rejects an observed control loss after five seconds
from SQL-update dispatch. That stricter fixture must pass independently and does
not replace console-dispatch or native/public validation. W5 remains open until
the required end-to-end evidence supports the owner-retained target.

The installed fixture additionally opens the real console, signs in locally and
confirms Revoke for its live native device. One browser-process monotonic clock
starts before confirmation, samples the private relay's actual proxy state and
retains thirty seconds without re-registration. Its receipt records the internal
console CA exception explicitly; it does not claim public/mobile acceptance.
The parent independently verifies unchanged native identity and Open grant, an
unexpired source grant despite fresh verified-TLS refusal, and the unrelated
original control/TLS route. This candidate fixture must run successfully before
its new receipt or screenshot can support native deadline acceptance.

Frozen-hook recovery reports original TCP loss, client recovery and Docker health
recovery separately. A reconnected client does not establish the healthy runtime
binding required by subsequent host operations. The fixture observes that health
recovery without forcing a restart; its separate recovery bound does not extend
the five-second cutoff measurement.

The isolated PostgreSQL harness additionally measures actual runtime-role snapshot
reads at 1,000, 10,000 and 100,000 revocations and rotation floors, then at the
combined 1,024-tenant/100,000-row bounds. It retains every case's wall time,
Go caller CPU and allocation observations and checks known denial, claim floors,
unrelated identity admission and transaction-local RLS scope. A 1,025-tenant case
checks refusal with the previous known denial retained. Synthetic rows remain inside
the disposable database until its volume is removed; no live credentials or
enrollments are manufactured. The one-second refresh budget is unchanged.
These measurements do not establish signed HTTP Ping throughput, frp continuity,
false cutoffs under a live fleet, or console/public five-second acceptance.

The stock-client fixture also defines five independent irreversible revocations
at preselected offsets of 0/200/400/600/800 ms after observing a successful Pong
in that client's private debug log. It records the actual observed-Pong-to-SQL
dispatch offset; log polling requests a 10 ms interval, which is an observation
resolution rather than an exact packet timestamp. Each case independently
requires cutoff within five seconds of SQL dispatch, the client's error Pong,
server Ping refusal, a fresh official-client Login refusal, new TLS refusal and
the same unrelated original TCP controls throughout the sweep. Completed revoked
clients stop before the next case so old retries cannot satisfy new evidence.
A single preparation wait clears the existing enrollment-token rate window;
timed revocations are never retried. Every attempted case is retained, including
failures. This fixture has to execute successfully before its results are accepted.
It does not measure the cache refresh phase directly or replace the required
console/native/public and live-fleet tests.

The small-fleet fixture prepares five, then ten additional identities through
ordinary authenticated enrollment and Open. It observes seven, then twelve live
official frpc controls including the two original witnesses for 30 seconds per
stage. Original TCP inodes remain unchanged across both stages and their
preparation waits. Each stage requires successful per-client Pongs and
verified TLS before and after each stage, with no client or service restart.
It reports authz/frps process CPU and observed resident memory separately from
PostgreSQL/client/observer costs. Pong log observation gaps use requested 200 ms
polling and are not HTTP callback latency measurements. Preparation honors the
unchanged five-token minute limit; no failed timed stage is retried. All attempts
are retained. The dated checkpoint below records actual execution; changed inputs
need fresh checks. These small sizes do not establish capacity for a larger fleet
or complete the public/fault/migration gates.

A third 30-second case keeps all twelve controls and loads 99,000 synthetic
revoked-device rows plus 99,000 rotation floors into that same disposable
single-tenant database. Rotation bindings are inserted while their synthetic
devices are active, then revoked in the same transaction; no signed claims or
enrollments are manufactured. These rows remain until owned database teardown.
Their reserved canonical UUID range sorts after genuine v4 enrollments, so the
ordinary interface fixtures retain their existing first-page visibility.
The 1,000-row margin preserves the ordinary fixtures' later irreversible
revocations. The original control inodes must survive preparation and the timed
case; successful Pongs and verified TLS remain required. It records actual row
counts and authz/frps process cost, rather than inferring combined continuity
from the separate SQL-only load run. Subsequent outage/freeze and five-phase
revocation cases run with these rows retained; the later native console check
also inherits that data. Revocation identities use fresh ordinary enrollment
tokens after pressure preparation. The dated checkpoint below records its execution. It does
not establish 99,000 online clients, PostgreSQL CPU cost, public-network behavior
or direct cache-publication phase timing.

The candidate also reads each dedicated authz, frps and PostgreSQL cgroup's CPU
counter and charged memory, including descendant tasks. It binds the exact
Docker container and original cgroup inode, requires cgroup v2 and retains each
counter's measurement window. Charged memory includes cache and is distinct from
the process RSS above. These counters exclude clients and the observer. Their
PostgreSQL cost must be backed by actual measurements; no local estimates are accepted.

## Scoped pressure execution checkpoint

Source `1624ff9` passed complete [CI 43377788586](https://github.com/KazuhaHub/nethub/actions/runs/43377788586).
The disposable deployment retained 99,000 synthetic revoked rows and 99,000
rotation floors. All twelve original controls survived the 30.051-second pressure
stage, with 299 observed Pongs and a maximum observed gap of 1,210 ms. Dedicated
authz/frps/PostgreSQL cgroups averaged 0.4102/0.0080/0.1875 CPU cores; charged
memory includes cache and is separate from process RSS. These are bounded
measurements, not 99,000 online clients or production capacity.

The ten additional clients stopped before later faults and the five-phase sweep;
the synthetic database rows remained. SQL-dispatch cutoffs were 1,097, 1,927,
1,645, 1,510 and 1,249 ms. These are not before-console or public timings.
The same source's installed run failed in its earlier relay prerequisite, before
starting the native guest. It supplies no WAN recovery or native console cutoff.
The failure and cleanup are retained; the original relay cause was not exported.
The earlier source `d6f1b43` failed at native WAN change with restoration attempted
but not verified. Later fixture changes need their own exact-source execution;
neither checkpoint completes W5 or public/mobile, direct cache-phase, larger-fleet,
short-network and migration/rollback gates.

Source `d5c0d5f` subsequently passed complete
[CI 43382960743](https://github.com/KazuhaHub/nethub/actions/runs/43382960743).
With the same synthetic row counts, twelve original controls survived 30.039
seconds, with 298 Pongs and a maximum observed gap of 1,224 ms. Dedicated
authz/frps/PostgreSQL cgroups averaged 0.4440/0.0094/0.2831 CPU cores.
Its five SQL-dispatch cutoffs were 2,102, 1,975, 1,692, 1,545 and 1,275 ms.
The same scope limits apply. Its installed run passed the standalone WAN change
and restoration checks but later failed at a read-only SSH inspection following
Rotate; it does not complete native or public console revocation acceptance.
