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

## Rebuilt package check

The unsigned 0.0.14 package was built from
`aaf0dbe0fd8a1fac5fb8686afcf2801a5b0f4032` on the native appliance in
348.7 seconds, with no swap-page increase. Its SHA256 is
`267d6f2f72f347d9f434991768c22b331cca64d971bd34db06021778e8f83781`.
Independent archive inspection confirmed matching package/model/product versions,
the native-tested runner bytes and all four updated trust/GUI caller prefixes.
The package, build log and hash manifest were exported before restoration.

A separate guarded installation passed `pkg check -s`. Its actual certificate
cron prefix, including the 45-second runner and shared lock, invoked the installed
`NativeGuiBackend._restart()` through a private fixture script. It returned 0 in
1.143 seconds. The original TLS leaf and HTTP status then remained stable for
48.452 seconds. The restart left the configuration unchanged and preserved the
operator's stopped tunnel intent. The installed forget prefix was inspected;
neither cron dispatch nor configd forget dispatch was exercised in this fixture.

Installation changed only the native model version, its save timestamp, the new
empty trust-state field and revision metadata. Existing model values and all
unrelated native configuration were checked structurally. Early harness runs
incorrectly required byte-identical configuration or assumed an integer save
timestamp; their failures were retained and corrected against exported native
before/after snapshots. A subsequent restart assertion lacked an exported child
diagnostic and is not counted as passing evidence. The successful run exported
its receipt before the independent checkpoint guard restored the appliance.

These comparisons verify restart behavior, not certificate issuance,
installation, renewal or browser enrollment. The TLS probes compared identity
without validating a public trust chain. The full native certificate pipeline
still requires separate acceptance. The appliance used the owner's approved
1 GiB test allocation; no production sizing claim is made. The test package was
neither signed nor published as a release.
