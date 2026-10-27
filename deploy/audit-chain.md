# Read-only audit verification

`nethub doctor --audit` checks one deployment tenant's audit history in a
read-only, repeatable-read PostgreSQL snapshot. It verifies contiguous sequence
numbers, previous-hash links and each SHA256 digest. It reports counts, not raw
audit entries, and returns no partial-success result when verification fails.

Run it inside an existing Web container after migration and a tested image
upgrade. This uses the existing Web-role password file without publishing the
database or starting a second statically addressed Web container:

```sh
cd /srv/nethub-deployment
docker compose exec -T nethub-web /nethub doctor --audit \
  --host postgres --database nethub \
  --password-file /run/secrets/pg_nethub_web --sslmode disable
```

The explicit database TLS disable applies only to the generated isolated Docker
network. For another database topology, use the default `verify-full` and its
reviewed connection settings. The command fixes the role to `nethub_web`; it does
not need owner credentials, run migrations, create an account or repair data.
File/DNS and private-health checks are separate modes; combining their flags with
audit mode is refused.

## Encoding and compatibility

Migration 26 adds `hash_version`. Existing rows are marked version 1 without
changing their stored content, hashes or links. The original append function
serialized timestamps in its PostgreSQL session timezone. To verify such rows,
select their original writer timezone with `--audit-timezone`; the default is
`UTC`. Names must exist in PostgreSQL's timezone catalog. A wrong or unknown
legacy timezone fails verification rather than rewriting history. Mixed legacy
writer zones may not be verifiable with one selection.

New appends through the controlled function use version 2. The hashed document
includes the version and an explicit UTC timestamp with six fractional digits.
It is independent of the writer session's timezone and continues from the prior
stored hash, including a version-1 predecessor. Web and authz still serialize
appends through the same tenant-row lock. The verifier orders by sequence, not
wall-clock time, and does not take an append lock.

Both versions use PostgreSQL JSONB text encoded as UTF-8. Database serialization
or future codec changes need their own compatibility proof and version; existing
hashes must not be silently regenerated.

## Bounds, results and investigation

The total command budget defaults to 30 seconds. `--audit-timeout` accepts one
second through five minutes and includes connection, tenant selection and reading.
A canonical record larger than one MiB is not transferred for verification.
Oversized, unsupported, inconsistent or unreconstructable records stop the check.
This is a verifier resource limit, not a new table constraint or a deletion rule.

Exit 0 means the visible snapshot's linked history verified. Exit 1 means the
connection/check was unavailable or history could not be verified; exit 2 means
invalid options or incompatible modes. Verification diagnostics do not print
payloads, credentials or raw database errors. On failure, preserve a database
snapshot and investigate the reported class of problem, migrations, original
legacy timezone, record size and stored history. No repair operation is provided.

The chain detects accidental inconsistency. An owner can rewrite a complete
chain, and a valid remaining prefix cannot reveal tail truncation without an
independent checkpoint. It does not establish truthful events from compromised
actors, forensic integrity, successful backup/restore or complete doctor/W7
acceptance.

## Validation scope

Unit checks cover record/sequence/link/digest/version and CLI mode boundaries.
The genuine PostgreSQL suite includes historical migrations and retained hashes,
legacy timezone selection, concurrent Web/authz appends in different zones,
readers during append locks, tenant/role refusal, corruption and a correctly
hashed oversized record. It invokes the compiled CLI with the Web credential and
checks that failure neither discloses its private fixture payload nor repairs it.
Hosted execution and acceptance must be verified at the exact source revision;
local compilation or skipped database tests do not establish these SQL results.

PR #185 passed all six checks in run `40420387566`, including actual historical
SQL and compiled-command execution, inherited deployment/IdP regressions and
owned cleanup. All eight final image hashes and visuals were reviewed, and the
merged tree equals the tested tree. This is W7-1 acceptance within the limits
above; the other doctor, backup/restore, rotation and release gates remain open.
