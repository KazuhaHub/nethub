# Native relay trust integration

On 2026-10-22, source `e6ce45c6686200297b2b33918914b3ae5b6329e6`
passed 625 actual OPNsense source/model tests with one JSON Schema skip.
Exact-head CI run 39699687722 passed all six jobs, including 708 plugin tests
with eight platform skips, the full Linux Go race suite and vet, real PostgreSQL
authorization/concurrency cases, and protected issuance/renewal/account flows.
These results establish the tested components, not the remaining rollout gates.

The unsigned development package was version 0.0.12, SHA256
`3af38de19479bf24203c4f97eae081ae9d4b26acf39e42255bd6f17dc93c7b19`.
Its frpc 0.71.1 client was rebuilt with Go 1.26.10; binary identity and linked
licenses were verified. An independent planner pinned complete package metadata,
scripts, 92 file contents and permissions before installation. The native
migration preview matched the candidate model and permitted only the agent
namespace. System and unrelated plugin configuration remained unchanged.

An independently rehearsed host watcher protected installation with a pinned,
powered-off checkpoint of the dedicated test VM. Actual upgrade, namespace
migration, native checksums, configd and stopped intent passed. The existing cron
daemon executed the trust task without being restarted, and the configd action
returned the expected inactive result for the unenrolled lab.

After an actual guest reboot, the migrated model and stopped intent remained.
Cron executed again, the original pinned GUI TLS/GET probe passed, and wildcard
template generation did not recreate the archived old tunnel candidate. The
explicit-only template marker still permits the agent's explicit module reload.

Actual removal deleted every package file and its cron entry without restarting
cron. A read-only inverse of stock plugin unregistration verified the retained
agent model and unchanged system/unrelated configuration; that projection was
never saved. The independent watcher then restored the original 0.0.6 package,
exact configuration, permissions, runtime, stopped intent and pinned GUI probe.
The old version's boot candidate was independently reproduced from the original
configuration and pinned template before comparison.

Source, package, independent package plans, raw phase logs and receipts were
exported with hashes before checkpoint restoration. Pre-reboot evidence was
exported before requesting the reboot. Early observations encountered SSH and
cron startup delays; their failed observations were retained, and checks passed
after the services became ready. The earlier run's missing-log limitation no
longer applies to this refreshed installation/reboot/removal evidence.

This was an inactive, unenrolled baseline lifecycle test using the approved
1 GiB lab exception. It does not prove live trust installation/report retry,
root overlap/retirement, offline recovery, bootstrap authority migration,
quarantine or the combined public/native GUI certificate flow. Those scenarios
remain required. The package was neither signed nor published as a release.
