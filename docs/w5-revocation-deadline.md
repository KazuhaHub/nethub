# Five-second revocation target

Kazuha retained the five-second target on 2026-11-12 and authorized changes to
heartbeat and revocation processing. The original installed result, 17.218 seconds
from console confirmation dispatch, remains a failed timing comparison. Do not
replace it with an easier threshold or restart the clock at database commit.

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
are retained. This fixture still needs actual execution; these small sizes do not
establish capacity for a larger fleet or complete the public/fault/migration gates.
