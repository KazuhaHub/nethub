# Heartbeat revocation and explicit disconnect validation

PR [159](https://github.com/KazuhaHub/nethub/pull/159) added console Revoke and
corrected the callback path used by host-network frps. PR
[160](https://github.com/KazuhaHub/nethub/pull/160) added explicit disconnect
requests for already revoked enrollments. Both are merged. These are hosted
deployment and contract results; combined installed-appliance/public W5 acceptance
remains open.

## Accepted sources

| Change | Tested head | Six-job run |
| --- | --- | --- |
| Console Revoke and callback publication | `71f632625e56b9d92b178d08db0ab145b37c03c6` | [40139737460](https://github.com/KazuhaHub/nethub/actions/runs/40139737460) |
| Explicit disconnect after main synchronization | `507c3fe0a56535bebfb56c386f12a4b4a4c3e759` | [40140708134](https://github.com/KazuhaHub/nethub/actions/runs/40140708134) |

Actual logs, inherited deployment/authority gates, eight/five signed commits and
full fetched credential history with ten exception controls were checked before
each merge. Appliance/plugin and protocol sources were bound to the unchanged
complete archive from the earlier FreeBSD proof; this was not a fresh native run.

## Official frp observations

The fixture uses the pinned official clients, generated production configuration,
the deployed authz process and authenticated private frps admin observations. Two
original enrollments remain available for later authority tests; a separate third
enrollment is permanently revoked. No enrollment is made active again.

| Observation after command dispatch | PR 159 | Final PR 160 |
| --- | ---: | ---: |
| Authz stop command completed | 0.224 s | 0.248 s |
| First sampled with original client sockets gone | 8.831 s | 8.999 s |
| Both original proxy registrations removed | 8.843 s | 9.015 s |
| Proxy removal after confirmed authz stop | 8.618 s | 8.768 s |
| Recovery after authz restart | 1.067 s | 1.075 s |
| Dedicated revoked proxy removed | 9.792 s | 9.803 s |

Socket and proxy results are observation bounds, not exact packet timestamps.
The stopped container was independently confirmed not running and not OOM-killed.
The loopback callback refused connections immediately at millisecond resolution.
Actual Ping rejection and subsequent fresh Login rejection were recorded; the
unrevoked device retained verified TLS.

An earlier failed run retained original-socket count zero at its 45-second gate,
but proxy registrations disappeared only at 53.341 seconds during a diagnostic
extension. That gate remained failed. The corrected deployment calls authz through
its host-loopback publication instead of a removed bridge endpoint. This verifies
the stopped-container path; it does not establish a general deadline for upstream
frp's HTTP client or a suspended dependency. Current tests separately retain
dispatch time, confirmed-stop time, original sockets and proxy state.

## Authorization and receipt proof

Genuine PostgreSQL tests covered owner/admin/tenant scope, disabled actors, eight
concurrent exact retries, first timestamps, normalized-source audit, audit-failure
rollback, revoked Open denial and narrow role grants. Disconnect requests require
an already revoked identity and retain immutable first receipts.

The compiled authz process handled a genuine web-role request only after its
published memory snapshot denied the tenant/device. Arming and audit commit
together; failure remains pending. Strict-CSP browser tests covered confirmation,
Cancel/Escape without mutation, explicit retry, revoked Open and the polled
heartbeat-ready state. That state does not claim every existing stream closed.

Anomaly confirmation/actions, installed circuit behavior, unchanged config.xml,
reboot/configuration restoration and the combined native/public/mobile W5 flow
still require their own implementation and acceptance.
