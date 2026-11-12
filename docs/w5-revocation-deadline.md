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
