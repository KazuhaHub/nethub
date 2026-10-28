# Restricted backup worker

The worker starts one attempt immediately, waits 24 hours after success and retries failures after one hour. Defaults are a ten-minute total budget, a ten-GiB custom-archive limit and thirty-day retention. Options are validated before I/O; the deployment fingerprint comes from the actual read-only backup connection.

Each cycle verifies the private storage and password file, checks backup-role privileges and deployment identity, runs PostgreSQL 16 `pg_dump`, verifies the complete archive and applies retention. The archive lock serializes publication, retention and recorded caller failures. Retention preserves the verified latest success and fresh or unmanaged files, checks all candidates before deleting, and refuses unsafe file types or permissions.

The process holds a separate private runtime lock. Every start resets volatile health to `starting`; only a complete successful cycle updates its healthy timestamp. Failed preflight or retention marks runtime health unhealthy even when an older archive is fresh. Failure records retain previous archive identity and refuse overwriting a newer attempt or success. Failure to publish health stops the daemon. Parent cancellation stops the active attempt and releases the runtime lock.

`nethub backup run` performs one maintenance cycle. `backup serve` runs the daily worker. `backup health` checks live-worker phase and recent archive metadata; `doctor --recent-backup` derives deployment identity from the database and hashes the complete archive. The latter has a configurable bounded verification budget and does not require a running daemon.

The dedicated Dockerfile `backup` target contains the application, PostgreSQL client tools and their pinned runtime files. Its non-root Compose service has only the database network, its own password mount, a private archive volume and a separate private runtime tmpfs. Actual container and isolated restore checks passed the [scoped checkpoint](../../../deploy/validation-database-backups.md). Full clean-host control-plane/key restoration and enrolled-device reconnection remain separate W7 requirements.
