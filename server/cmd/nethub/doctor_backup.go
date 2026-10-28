package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/dbbackup"
	"github.com/KazuhaHub/nethub/server/internal/store"
)

type backupDoctorOptions struct {
	Database        store.DatabaseConfig
	Directory       string
	MaxAge, Timeout time.Duration
}

func runBackupDoctor(options backupDoctorOptions, stdout, stderr io.Writer) int {
	if dbbackup.CheckArchiveAccess(options.Directory, options.Database.PasswordFile) != nil {
		fmt.Fprintln(stderr, "Backup inputs are unavailable; run in the Linux backup runtime with private owned archives and the backup-role password file")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout)
	defer cancel()
	db, err := store.OpenRole(ctx, options.Database, "nethub_backup")
	if err != nil {
		fmt.Fprintln(stderr, "Backup database connection failed; check the database service, TLS settings and backup password file")
		return 1
	}
	fingerprint, err := store.BackupDeploymentFingerprint(ctx, db)
	db.Close()
	if err != nil {
		fmt.Fprintln(stderr, "Backup identity check failed; review the read-only backup role and the single-tenant database identity")
		return 1
	}
	status, err := dbbackup.VerifyWithBudget(ctx, options.Directory, fingerprint, options.MaxAge, options.Timeout)
	if err != nil {
		switch {
		case errors.Is(err, dbbackup.ErrBusy):
			fmt.Fprintln(stderr, "Backup state changed during verification; retry after the current attempt finishes")
		case errors.Is(err, dbbackup.ErrStale):
			fmt.Fprintln(stderr, "No recent completed backup; inspect the backup service and complete a fresh restricted database backup")
		case errors.Is(err, dbbackup.ErrLastAttempt):
			fmt.Fprintln(stderr, "Latest backup attempt failed or exceeded its budget; inspect the service log and complete a successful retry")
		default:
			fmt.Fprintln(stderr, "Backup verification failed; preserve existing archives and review their ownership, receipt and full-file integrity")
		}
		return 1
	}
	fmt.Fprintf(stdout, "Recent database archive integrity and freshness passed (%d bytes, PostgreSQL %s)\n", status.Receipt.Bytes, status.Receipt.DumpVersion)
	return 0
}
