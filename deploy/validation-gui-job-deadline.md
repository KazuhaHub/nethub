# Native GUI job deadline regression

An isolated OPNsense 26.7.7 / FreeBSD 15.1 test reproduced the daemon ownership
problem previously found in trust synchronization. The stock web GUI restart
returned through a daemon launcher, but FreeBSD `timeout` continued tracking its
descendants and stopped the management service at the deadline.

The controlled comparison used the existing appliance certificate and an
eight-second fixture deadline:

| Invocation | Exit | Duration | Subsequent observation |
| --- | --- | --- | --- |
| Stock `timeout -v -k 1 8 rc.restart_webgui` | 124 | 8.297 s | GUI unavailable |
| Untimed stock restart, for recovery | 0 | 0.575 s | Original TLS leaf and HTTP status restored |
| `run_bounded.py 8 rc.restart_webgui` | 0 | 0.901 s | Same TLS leaf and HTTP status stable for 12.181 s |

The runner matched SHA256
`7b2f10b07c079f45b2aad071358455323fd9c006b169624b96e092d27e41c8b7`,
the source covered by the five native process controls in the
[trust deadline validation](validation-relay-authority-native.md).
The fixture did not pass the stock restart's certificate regeneration argument.
The native configuration and certificate identity remained unchanged.
Private logs and receipts were exported outside Git. An independent checkpoint
guard restored the original package, configuration and stopped tunnel intent;
a subsequent SSH check verified that baseline. No relay services were changed.

The package now uses the same runner for the 45-second certificate cron task
and the 35-second configd `forget` task. Forget can recover a pending certificate
transaction, which can restart the GUI. Both retain the shared mutation lock
and their existing deadlines. Report and unenroll retain their existing
timeouts: their recovery paths do not start the GUI or a new tunnel.

This comparison verifies stock restart behavior, not certificate issuance,
installation, renewal or browser enrollment. The TLS probe compared identity
without validating a public trust chain. A rebuilt package and the full native
certificate pipeline still require separate acceptance. The appliance used
the owner's approved 1 GiB test allocation; no production sizing claim is made.
