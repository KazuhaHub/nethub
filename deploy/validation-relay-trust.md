# Standalone relay trust transport

On 2026-10-22, actual Linux frps and FreeBSD frpc 0.71.1 passed an isolated
old/overlap/new trust experiment. This validates the transport components;
authenticated distribution, native model application and production authority
transitions remain separate acceptance work.

## Tested inputs and boundary

The Linux relay was built with Go 1.26.10 from the locked relay module at
`395413e`; its actual binary vulnerability scan was clear. Its SHA256 was
`78e804e6d276fbd422191700ada54f1d2eb30f69d52400655a13281f29741940`.
The native client came from the exported unsigned 0.0.12 package built at
`e6ce45c`, with SHA256
`8f29ddf322976862fbed3cd4746273cdfa631484a8ad7f7c45c39b096a89755a`.
Its build identity was Go 1.26.10, FreeBSD amd64 and frp 0.71.1. The native
receiving helper independently verified all three canonical public bundles.

These inputs are unchanged in the accepted PR #105 implementation. The installed
0.0.6 lab plugin was left untouched; its binary was not used for this experiment.
The approved 1 GiB OPNsense lab deviation applies.

The relay ran as UID 65532 with forced TLS, token authentication, one allowed TCP
proxy and loopback-only control/proxy listeners. A pinned SSH forward bound to
the Hyper-V private LAN carried control traffic. The LAN adapter's MAC and guest
route were checked before starting it. Existing public listeners and services
were not changed. Disposable issuer keys stayed outside runtime; actual
dropped-UID probes confirmed the relay identity could not read them.

The native client used explicit CA files and server-name verification, 10/30
heartbeats and automatic reconnect. A bounded loopback echo service provided
fresh challenge/response evidence through the actual frp proxy. No console,
tenant, device enrollment, database grant or production signer was substituted
by these standalone peers.

## Observed results

All twelve recorded phases passed, including the following cases:

| Case | Result |
| --- | --- |
| Old trust with old leaf | Actual proxy challenge/echo passed. |
| Overlap trust with old and then new leaf | Both passed. Restarting only frps retained the native frpc PID and recovered echo. |
| New-only trust with new leaf | Passed. |
| New-only trust with an old served leaf | No proxy data passed while both peers remained alive. An independent native TLS check refused the chain with verification code 20. |
| Return to the new leaf | Echo recovered with the same native frpc PID. |
| Fresh old-trust client joining a new-leaf relay | Refused; supplying verified current trust restored the proxy. This represents the transport failure/recovery path of a stale peer, not a complete offline-device workflow. |
| Wrong server name | No proxy data passed. Independent native TLS verification returned hostname-mismatch code 62; the correct name/current trust then passed. |

The observed upper bounds from the relay restart command to verified echo were
4.344 seconds for the overlap-to-new-leaf switch and 18.829 seconds after returning
from the refused old leaf. These include SSH/control operations, retry backoff
and probe/status observation. They are not precise connection-outage durations
or production latency guarantees. The post-command probe delays were recorded
separately in the private evidence.

frp can report a generic `session shutdown` after a failed connection rather than
the underlying certificate error. Earlier experiments withheld acceptance when
that diagnostic was insufficient. The final experiment additionally used native
TLS contexts containing only the selected CA bundle, mandatory hostname checks
and frp's TLS preface. It pinned the actual served leaf fingerprint with a valid
trust context, verified refusal with the invalid context, and repeated the valid
fingerprint check after the denial window. Actual frpc traffic refusal and live
process checks remained mandatory; log text alone was not treated as proof.

## Cleanup and retained evidence

Independent external timeouts bounded both remote process groups. A separate
deadline rehearsal on Linux and FreeBSD confirmed that the actual timeout killed
an owned child and grandchild without coordinator cleanup; both returned 124 and
left no running probe process. Normal and failed experiment cleanup also passed.

Before cleanup, raw logs, per-phase results and exact harness sources were
exported. Both peer process sets, the SSH forward, private parameter files and
disposable signing/leaf keys were removed. Existing public listener identities,
the original OPNsense configuration, installed package and stopped intent matched
their preflight state. Public test certificates and private evidence were retained.

The final private evidence contains 62 files. Its manifest SHA256 is
`7a130228dba882e5ddd92f0f42674c45d4cf2f36d8b7c66f8922293caba7e71a`.
Operational addresses, credentials, raw logs and signing material are not included
in this repository. The failed observations remain preserved separately.

## Remaining product acceptance

This experiment does not prove authenticated console delivery, actual native
model/file application and lost-receipt retry, database retirement barriers,
offline quarantine/recovery or protected authority/backup migration. It does not
cover the combined public/native GUI issuance and renewal flow. Those gates,
along with W5-W7, remain open. No public CA account, release signing or formal
package publication was performed.
