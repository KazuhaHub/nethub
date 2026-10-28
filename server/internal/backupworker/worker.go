// Package backupworker coordinates restricted archives, retention and daemon health.
package backupworker

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/dbbackup"
	"github.com/KazuhaHub/nethub/server/internal/store"
)

var (
	ErrOptions   = errors.New("invalid backup options")
	ErrStorage   = errors.New("private backup storage or password file unavailable")
	ErrDatabase  = errors.New("backup database connection failed")
	ErrAuthority = errors.New("read-only backup role or deployment identity check failed")
	ErrArchive   = errors.New("database archive attempt failed")
	ErrRetention = errors.New("backup retention failed")
	ErrDeadline  = errors.New("backup cycle exceeded its time budget")
	ErrHealth    = errors.New("backup worker health could not be published")
)

var databaseName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)

type Config struct {
	Backup    dbbackup.Config
	Retention time.Duration
}

type Result struct {
	State   dbbackup.WorkerState
	Receipt dbbackup.Receipt
	Pruned  int
}

// Validate rejects invalid options before filesystem or network operations. The
// deployment fingerprint is always derived from the actual backup connection.
func Validate(config Config) error {
	c := config.Backup
	if c.DeploymentFingerprint != "" || c.Host == "" || len(c.Host) > 255 || strings.ContainsAny(c.Host, "/\\\r\n\x00 =") || !databaseName.MatchString(c.Database) || c.Port == 0 || c.SSLMode != "verify-full" && c.SSLMode != "disable" || c.Timeout < time.Second || c.Timeout > 30*time.Minute || c.MaxBytes < 1024 || c.MaxBytes > 1<<40 || config.Retention < 24*time.Hour || config.Retention > 365*24*time.Hour {
		return ErrOptions
	}
	for _, path := range []string{c.Directory, c.RuntimeDirectory, c.PasswordFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return ErrOptions
		}
	}
	return nil
}

// Attempt performs one bounded cycle. Its caller holds the private runtime lock
// throughout the worker lifetime. Database messages and credentials are never
// returned as diagnostics; failures retain the previous healthy-cycle timestamp.
func Attempt(parent context.Context, config Config, previous dbbackup.WorkerState) (Result, error) {
	var result Result
	if err := Validate(config); err != nil {
		return result, err
	}
	started := time.Now().UTC()
	state := dbbackup.WorkerState{Version: 1, Outcome: "running", AttemptStartedAt: started, AttemptDeadline: started.Add(config.Backup.Timeout), LastSuccessfulCycleAt: previous.LastSuccessfulCycleAt, DeploymentFingerprint: previous.DeploymentFingerprint}
	result.State = state
	if dbbackup.WriteWorkerState(config.Backup.RuntimeDirectory, state) != nil {
		return result, ErrHealth
	}
	ctx, cancel := context.WithDeadline(parent, state.AttemptDeadline)
	defer cancel()
	fail := func(reason error, phaseStarted time.Time) (Result, error) {
		state.Outcome = "failed"
		result.State = state
		publishErr := dbbackup.WriteWorkerState(config.Backup.RuntimeDirectory, state)
		failureCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		// An existing newer success or a busy archive is left unchanged. Runtime
		// health still reports this worker's own failed phase independently.
		_ = dbbackup.RecordFailedAttempt(failureCtx, config.Backup.Directory, phaseStarted, config.Backup.Timeout)
		if publishErr != nil {
			return result, ErrHealth
		}
		return result, reason
	}
	if dbbackup.CheckStorage(config.Backup.Directory, config.Backup.RuntimeDirectory, config.Backup.PasswordFile) != nil {
		return fail(ErrStorage, started)
	}
	db, err := store.OpenRole(ctx, store.DatabaseConfig{Host: config.Backup.Host, Port: config.Backup.Port, Database: config.Backup.Database, PasswordFile: config.Backup.PasswordFile, SSLMode: config.Backup.SSLMode}, "nethub_backup")
	if err != nil {
		return fail(ErrDatabase, started)
	}
	fingerprint, err := store.BackupDeploymentFingerprint(ctx, db)
	db.Close()
	if err != nil {
		return fail(ErrAuthority, started)
	}
	options := config.Backup
	options.DeploymentFingerprint = fingerprint
	result.Receipt, err = dbbackup.Run(ctx, options)
	if err != nil {
		if errors.Is(err, dbbackup.ErrBusy) {
			return fail(dbbackup.ErrBusy, started)
		}
		return fail(ErrArchive, started)
	}
	retentionStarted := time.Now().UTC()
	result.Pruned, err = dbbackup.Prune(ctx, options.Directory, fingerprint, config.Retention)
	if err != nil {
		return fail(ErrRetention, retentionStarted)
	}
	completed := time.Now().UTC()
	if ctx.Err() != nil || completed.After(state.AttemptDeadline) {
		return fail(ErrDeadline, retentionStarted)
	}
	state.Outcome = "succeeded"
	state.LastSuccessfulCycleAt = completed
	state.DeploymentFingerprint = fingerprint
	result.State = state
	if dbbackup.WriteWorkerState(options.RuntimeDirectory, state) != nil {
		return result, ErrHealth
	}
	return result, nil
}
