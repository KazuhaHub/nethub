# Installed heartbeat outage and console revocation

A guarded operation installed the accepted unsigned 0.0.18 package from source
`db862f9`, matching all 46 packaged sources. The server used accepted runtime
`a69fa27`, frp 0.71.1 and generated production heartbeat/callback configuration.
The approved 1 GiB appliance deviation remains.

A fresh enrollment obtained one genuine public CA certificate through scheduled
application. A desktop browser used normal DNS and system trust to authenticate
to the public GUI after one real console Open click. The issuer was closed before
either fault experiment.

## Authz outage and recovery

The test stopped and restarted the same owned authz container. Its stopped state,
absence of an OOM kill and refused callback listener were independently observed.
Native TCP control sockets and actual frps admin proxy state were sampled.

| Measurement | Observed upper bound |
| --- | ---: |
| Stop dispatch to original control/proxy loss | 11.937 s |
| Confirmed authz stop to control/proxy loss | 9.906 s |
| Restart dispatch to verified public GUI | 17.766 s |

The only online proxy disappeared during the outage and returned afterward.
The native frpc PID, GUI key and frpc configuration remained unchanged. Recovery
required no manual agent start or reconcile; a fresh authenticated public GUI
browser passed afterward. These are sampled bounds for a stopped container,
not a general deadline for a suspended dependency.

## Real console Revoke

The normal confirmation dialog submitted exactly one Revoke request. Original
control sockets and the proxy were gone by 17.218 seconds after confirmation
dispatch. At that observation the same frpc process was still running and the
native revocation marker was absent: server rejection preceded the client's
subsequent revocation report.

Actual hook logs recorded both Ping and fresh Login denial. A new default-trust
browser connection and a TLS route probe were refused while the public TCP
listener remained reachable and the Open grant had not expired.

Across 54 samples and 374.172 seconds, no proxy reconnected. Normal native
reporting learned revocation and stopped frpc. The retained scheduler tail
independently contained six successful stopped reconcile records and one disabled
watchdog record. No manual agent stop/start/reconcile or revocation-marker write
was used during measurement. Native key and frpc configuration hashes stayed
unchanged.

**The W0 timing comparison remains open.** W0's immediate probe-mode rejection
disconnected in 2.136, 3.032 and 4.958 seconds. This product measurement includes
the real console mutation, database-to-memory revocation refresh and heartbeat
phase; its 17.218-second bound is longer. It establishes cutoff and a bounded
no-reconnect observation, but does not satisfy the PLAN row requiring the W0
range. No production timing setting was changed by this experiment.

## Cleanup and independent checks

Normal native UI removal succeeded. Original native configuration, package,
trust, restart script and stopped intent were restored, along with all fourteen
original server containers and listener owners. Independent window guards closed.
A separate guarded, read-only database inspection verified four issued jobs,
permanent revocation of all four retained devices, unchanged prior device/token/
request/job rows and immutable generation/application history.

Independent verification checked source bindings, initial Open evidence, actual
outage/revocation samples, raw scheduler bytes, certificate/application identity
and restored baselines. A review-script variable collision was corrected before
verification passed; it did not change experiment inputs or raw evidence. Private
operational details, credentials, certificate material and raw logs stay outside
Git.

The W5 mobile console Open sample remains untested. Historical W0 mobile success
does not replace it. The conditional alternative for a mechanism unable to cut
established tunnels does not apply to this observed cutoff. W5-W7 remain incomplete;
there is no signed release.
