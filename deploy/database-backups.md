# Database backups and recovery scope

The `backup` service creates a PostgreSQL 16 custom-format archive immediately
after startup, then 24 hours after each successful cycle. Failed cycles retry
after one hour. The actual container/restore checkpoint passed the
[scoped validation](validation-database-backups.md). It does not establish the
complete W7 clean-host recovery requirement.

The service uses only the `nethub_backup` password, the private database network,
a named `database-backups` volume and a private runtime tmpfs. It runs as UID/GID
65532 with a read-only root filesystem and no capabilities. Its image includes
`pg_dump` and `pg_restore`, but no database server, shell or privileged helper.
The isolated Compose database uses `sslmode=disable`; external database commands
default to `verify-full` with the image's normal system trust store.

## Operation and checks

Run commands from the generated deployment directory using its reviewed Compose
files and project. Initialization prints the required build command, including
the separate `backup` target. Do not mount all service secrets into this worker.

```sh
docker compose ps backup
docker compose logs --tail 30 backup
docker compose exec -T backup /nethub backup health
docker compose exec -T backup /nethub doctor --recent-backup \
  --backup-directory /var/lib/nethub-backups \
  --password-file /run/secrets/pg_nethub_backup --sslmode disable
```

The health command checks a live worker lock, bounded phase, a completed cycle
within 48 hours, and recent receipt/file metadata. It avoids hashing a potentially
large file on every health probe. The explicit doctor derives deployment identity
from the real read-only database connection and hashes the complete latest
archive. It does not restore the archive. A failed or overdue latest attempt
fails verification even if the previous good archive remains available.

The worker defaults to a ten-minute total cycle budget, a 10 GiB output limit and
30-day retention. Reviewed command overrides can change `--timeout` (one second
to 30 minutes), `--max-bytes` (1 KiB to 1 TiB), and `--retention-days` (1 to 365).
Increase the health start period along with any startup budget exceeding its
current eleven minutes; the protected runtime inspector intentionally rejects
health-check configuration outside the reviewed profile. Inspect failures before
retrying; increasing limits does not repair permissions or database authority.

Retention runs only after a new archive and its complete hash pass verification.
It keeps the latest successful archive, preserves unknown filenames and fresh
copies, and deletes only private managed archives whose filename timestamp and
filesystem modification time are both expired. An unsafe candidate refuses the
preflight before any deletions. Normal failure and cancellation remove temporary
passfiles and partial output. A hard process kill can leave incomplete archive
files; retention does not delete these or arbitrary operator files. Preserve and
review such files under private storage rather than treating them as successes.

## Custody and restoration

Archives contain device credentials, accounts and encrypted provider state. Keep
the volume and exported copies private, encrypted at rest where required, and
outside Git, public artifact stores and diagnostic uploads. A local named volume
is not off-host durability. Automated off-host transport is not implemented.
Protect any independently maintained copy and verify its hash after transfer.
Do not expose the Docker socket to the backup worker or change file ownership to
make an unrelated application able to read archives.

Preserve the matching deployment secrets, Web `secrets_key`, current relay
authority and certificates, and protected operation journals separately. The
initializer's immutable secret backup can predate later authority operations.
Archive identity is based on the retained single-tenant UUID, so credential or
certificate renewal does not invalidate it. Replacing keys or creating a new
tenant is not a restore procedure.

The isolated acceptance fixture restores an actual archive into a nonce-owned
database, compares device contents and checks Web column restrictions. It also
exercises failure/recovery, retention, corruption, daemon restart and controlled
cancellation. Its inserted device is a database fixture, not an enrolled appliance.
A complete clean-host control-plane restore with matching current keys and an
already enrolled device reconnecting remains unaccepted. Do not overwrite an
existing database or advertise a complete recovery command from these checks.

See [deployment boundaries](../docs/deployment.md#backup-and-restore-boundary),
[archive internals](../server/internal/dbbackup/README.md) and
[worker behavior](../server/internal/backupworker/README.md).
