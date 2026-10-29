# Scheduled database backup validation

Checkpoint source `a64a8e999589f52f7971d8219bc8c08128709e00` passed all six
required jobs in [run 40653818009](https://github.com/KazuhaHub/nethub/actions/runs/40653818009).
The nine commits carry human DCO sign-offs. Complete job logs and artifact
hashes were checked; thirteen primary and four supplemental browser images were
visually reviewed. This records a tested checkpoint in PR #191, not its merge.

Final source `ec242255f1951b4fe3d2f5e2c1eefa0e31fc6460` passed all six jobs in
[run 40657579668](https://github.com/KazuhaHub/nethub/actions/runs/40657579668).
Complete actual/inherited logs, ten human DCOs and all seventeen final image
hashes/visuals were checked. PR #191 merged as `b03e23829f66e78f82618a546bc6de62eb52bcf3`;
the tested and merged trees are both `91f136d1df5ff98193d121553e53b70f059133df`.
The limitations below remain unchanged.

## Actual container and database checks

The assembled nonroot client-only image passed directory ownership/mode and
PostgreSQL client execution checks before stack startup. Its real restricted
dump was restored into a separate owned database; ordered device contents
matched without publishing rows or archives. Web column boundaries and backup
role metadata refusals passed against actual PostgreSQL.

The worker passed startup, health, deep full-hash doctor, restart, retention,
same-size corruption refusal, failed preflight/output limits and last-good
preservation/recovery. An unsafe retention candidate refused before deletion;
fresh and unmanaged files remained. Cancellation during an actual dump blocked
on a controlled database lock terminated within ten seconds and removed partial
output and temporary credentials. Restart then produced a healthy archive.
Runtime tmpfs inspection used the verified live process namespace. Owned
resources were removed, and the six-service runtime inspector rejected unexpected
Web and backup secret files before recovering with the services unchanged.

All five assembled deployment images passed the existing HIGH/CRITICAL scans
without exclusions. The pinned JOSE migration passed focused production API
tests, real Caddy issuance/renewal cases and source/binary vulnerability checks.
The [Caddy build note](images/caddy/README.md) retains the unreleased dependency
pin and upstream package-test limitation.

## Evidence boundaries

Earlier fixture-input, dependency compilation/scan, startup, image-directory and
tmpfs-inspection failures remain retained as failed attempts. The final run
recovered those checks; an unsupported tmpfs copy did not establish credential
residue. Raw provider diagnostics, archive contents and operational identities
remain outside Git.

The retained native FreeBSD contract archive differs from this source only in
the client's two Go dependency locks for JOSE 4.1.6. All other archived source
bytes match. The actual native filesystem contracts remain tied to their original
run; the current client separately passed a real FreeBSD-target build and
source/binary vulnerability checks with matching lock hashes. This does not claim
that the newly built client was installed or retested on an appliance.

The isolated restored database is not the full W7-5 clean-host recovery drill.
Current deployment keys/control-plane restoration, an already-enrolled native
device reconnecting after that restore and off-host backup durability remain
open. Independent external port witnesses and agreement with a formally
published appliance package also remain open. W7-3, W7-5 and the full project goal
are incomplete. See [operations and custody](database-backups.md).
