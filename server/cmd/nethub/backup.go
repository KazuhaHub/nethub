package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/backupworker"
	"github.com/KazuhaHub/nethub/server/internal/dbbackup"
)

const backupUsage = `Usage: nethub backup <run|serve|health> [options]

  run     Create one private PostgreSQL archive and apply retention
  serve   Start immediately, then back up daily; retry failures after one hour
  health  Check the live worker and recent private archive metadata

Use the dedicated backup image with PostgreSQL 16 tools. Full archive integrity
verification belongs to the backup cycle and the doctor check.
`

func runBackup(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, backupUsage)
		return 2
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, backupUsage)
		return 0
	}
	if args[0] == "health" {
		return runBackupHealth(args[1:], stdout, stderr)
	}
	if args[0] != "run" && args[0] != "serve" {
		fmt.Fprint(stderr, backupUsage)
		return 2
	}
	flags := flag.NewFlagSet("backup "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "/var/lib/nethub-backups", "Existing private archive directory")
	runtime := flags.String("runtime-directory", "/run/nethub-backup", "Existing private volatile runtime directory")
	password := flags.String("password-file", "/run/secrets/pg_nethub_backup", "Private backup-role password file")
	host := flags.String("host", "postgres", "Database hostname")
	port := flags.Uint("port", 5432, "Database port")
	database := flags.String("database", "nethub", "Database name")
	tls := flags.String("sslmode", "verify-full", "verify-full, or disable for an isolated local database")
	timeout := flags.Duration("timeout", 10*time.Minute, "Total cycle budget, between one second and thirty minutes")
	maxBytes := flags.Int64("max-bytes", 10<<30, "Maximum custom-archive bytes")
	retentionDays := flags.Int("retention-days", 30, "Managed archive retention, between one and 365 days")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *port == 0 || *port > 65535 || *retentionDays < 1 || *retentionDays > 365 {
		fmt.Fprintln(stderr, "Backup options are invalid; check the port and retention range")
		return 2
	}
	config := backupworker.Config{Backup: dbbackup.Config{Directory: *directory, RuntimeDirectory: *runtime, PasswordFile: *password, Host: *host, Port: uint16(*port), Database: *database, SSLMode: *tls, Timeout: *timeout, MaxBytes: *maxBytes}, Retention: time.Duration(*retentionDays) * 24 * time.Hour}
	if backupworker.Validate(config) != nil {
		fmt.Fprintln(stderr, "Backup options are invalid; use absolute canonical paths, a valid database and bounded size/time limits")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reportedError := false
	report := func(result backupworker.Result, err error) {
		reportedError = err != nil
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintln(stderr, backupRemediation(err))
			}
			return
		}
		fmt.Fprintf(stdout, "Private database backup completed; %d expired archives removed\n", result.Pruned)
	}
	if args[0] == "run" {
		result, err := backupworker.Once(ctx, config)
		if err != nil && ctx.Err() != nil {
			fmt.Fprintln(stderr, "Backup interrupted")
			return 1
		}
		report(result, err)
		if err != nil {
			return 1
		}
		return 0
	}
	err := backupworker.Serve(ctx, config, report)
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(stdout, "Backup worker stopped")
		return 0
	}
	if err != nil {
		if !reportedError {
			fmt.Fprintln(stderr, backupRemediation(err))
		}
		return 1
	}
	return 0
}

func backupRemediation(err error) string {
	switch {
	case errors.Is(err, dbbackup.ErrBusy):
		return "Backup is already running; let the current operation finish before retrying"
	case errors.Is(err, backupworker.ErrStorage):
		return "Backup storage is unavailable; restore private owned directories and the backup password file"
	case errors.Is(err, backupworker.ErrDatabase):
		return "Backup database connection failed; check the database service, TLS settings and backup password file"
	case errors.Is(err, backupworker.ErrAuthority):
		return "Backup authority check failed; review the read-only backup role and the single-tenant database identity"
	case errors.Is(err, backupworker.ErrRetention):
		return "Backup retention failed; review protected archive state, permissions and the cycle time budget"
	case errors.Is(err, backupworker.ErrHealth):
		return "Backup health publication failed; restore the private writable runtime directory before restarting"
	case errors.Is(err, backupworker.ErrDeadline):
		return "Backup cycle timed out; review database/storage performance and the configured time budget"
	default:
		return "Database backup failed; check PostgreSQL 16 tools, backup role permissions and the configured size/time limits"
	}
}

func runBackupHealth(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("backup health", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "/var/lib/nethub-backups", "Private archive directory")
	runtime := flags.String("runtime-directory", "/run/nethub-backup", "Private worker runtime directory")
	maxAge := flags.Duration("max-age", 48*time.Hour, "Maximum successful archive/cycle age, between one hour and seven days")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *maxAge < time.Hour || *maxAge > 7*24*time.Hour {
		fmt.Fprintln(stderr, "Backup health requires a maximum age between one hour and seven days")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := dbbackup.CheckWorkerHealth(ctx, *directory, *runtime, *maxAge); err != nil {
		fmt.Fprintln(stderr, "Backup worker is unhealthy; inspect its log, runtime phase and recent private archive")
		return 1
	}
	fmt.Fprintln(stdout, "Backup worker is healthy")
	return 0
}
