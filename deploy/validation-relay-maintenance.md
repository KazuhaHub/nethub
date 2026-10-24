# Relay leaf maintenance acceptance

The W4 same-root relay certificate maintenance requirement is covered by actual
Linux/root deployment tests against accepted source `0b8398d`,
[run 40050210141](https://github.com/KazuhaHub/nethub/actions/runs/40050210141).
The current test files match the exact archived source. Actual job logs contain
the completion markers emitted after every assertion below.

| Requirement | Direct evidence |
| --- | --- |
| Automatically issue and apply changed material | An actual systemd timer invokes `nethub certificates maintain-relay` against a valid due leaf. Its new generation differs from both earlier generations and is no longer due. |
| Recover an application failure | The first frps recreation fails; the prior leaf remains served and both official clients retain usable tunnels after rollback. |
| Retry without reissuing | `--retry` applies the identical persisted candidate fingerprint. A subsequent ordinary scan keeps that generation and the same frps container. |
| Verify the served certificate | A fresh TLS connection checks the independent deployment CA, server name and exact served leaf fingerprint; both official frpc routes pass their own verified TLS probes. |
| Record recovery time | Retry dispatch to both verified clients took 547 ms in this hosted fixture. This includes command/probe time and is not an outage SLO. |
| Preserve authority and unrelated services | The CA private-key hash and unrelated container IDs remain unchanged; runtime leaf ownership/mode checks and the protected doctor pass. |

The same test also replaces an expired pending candidate, retains its superseded
material, applies a distinct valid generation and verifies both clients again.
Production service/timer templates pass systemd validation.

The earlier [native public LXC measurement](validation-w4.md#same-root-relay-leaf-maintenance)
recorded 4.0 seconds from maintenance trigger to fresh external verification of
both routes, including 17 failed and 62 successful fresh probes. Renewal has a
measured interruption; the hosted retry measurement is a separate observation.

This closes the relay leaf maintenance item only. The signing authority stays
on the protected host; this same-root operation does not rotate it. The two
clients are official Linux fixtures. Controlled native authority transitions
and device recovery have their [own evidence](validation-relay-authority-native.md).
Router GUI certificates have separate [native lifecycle](validation-native-gui-lifecycle.md),
[offline renewal](validation-native-offline-renewal.md), [rollback](validation-native-certificate-rollback.md)
and [identity-boundary](validation-native-certificate-identity.md) records.
Public CA, combined W4 and W5-W7 acceptance remain open.
