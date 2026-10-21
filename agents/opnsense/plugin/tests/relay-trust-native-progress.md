# Native relay trust integration

On 2026-10-21, source `6b075f09bff48529a72d5b04014c4ac63c72c1ab`
passed 613 native appliance tests with one CI-only schema skip. Two additional
schema modules passed 90 tests on the local dependency environment. Independent
private restoration components passed 170 native contracts. These checks do not
replace hosted CI or the remaining live trust rotation scenarios.

The unsigned development package was version 0.0.12, SHA256
`6972ef69f7ae8e0c11a94f591e806804c18b1a97a1e9e1ddbb8ade2f2b857d9d`.
Its complete metadata, lifecycle scripts, 48 file contents, native checksums and
permissions were pinned before installation. An actual native Core migration
preview ran in memory without saving. The installation migrated only the agent
namespace; an unrelated plugin's pending migration was left untouched.

A fresh powered-off Hyper-V checkpoint and an independently rehearsed host
watcher protected the actual installation. The upgrade, migrated model and
unchanged system/unrelated configuration passed checks. The existing cron
daemon ran the new trust task, and the actual configd trust action returned the
expected inactive result for the stopped, unenrolled baseline. After a guest
reboot, the migrated model, stopped intent, genuine cron execution and original
pinned GUI TLS/HTTP probe passed again.

The boot experiment exposed wildcard template generation writing a candidate
despite stopped intent. The target now uses OPNsense's explicit-only marker.
Tests against the native template engine verify that wildcard generation leaves
the candidate untouched while the agent's explicit module reload still renders
it with mode 0600. The actual reboot did not recreate the archived old candidate.

Actual package removal deleted its files and cron entry without restarting cron.
The original strict system check then refused stock plugin unregistration.
A separate read-only check reversed only that registration entry in memory;
the original system/unrelated hashes and expected retained agent model matched.
The projection was never saved. Scheduled host rollback subsequently restored
the original 0.0.6 package, configuration, permissions, stopped runtime and pinned
GUI probe. The old version's boot-generated candidate was independently
reproduced from the original configuration and pinned template before comparison.

Some raw experiment logs were not exported before scheduled rollback. Retained
receipts and observations establish the behaviors above, but a complete evidence
bundle still needs a repeat with immediate export after each phase. This is not
full W4 acceptance. Actual relay root overlap/retirement and offline recovery,
authority migration, quarantine behavior and the combined public/native GUI
certificate flow remain open. The approved 1 GiB lab exception still applies;
formal GUI certificate acceptance is not implied by the pinned existing leaf.
