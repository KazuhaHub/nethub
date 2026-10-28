// Package dbbackup creates private PostgreSQL archives and verifies recent results.
package dbbackup

import (
	"errors"
	"regexp"
	"time"
)

var (
	ErrUnavailable = errors.New("backup storage or configuration unavailable")
	ErrBusy        = errors.New("backup already running")
	ErrDump        = errors.New("restricted database dump failed")
	ErrIntegrity   = errors.New("backup archive or state could not be verified")
	ErrStale       = errors.New("no recent completed backup")
	ErrLastAttempt = errors.New("latest backup attempt failed or exceeded its budget")
)

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var archivePattern = regexp.MustCompile(`^nethub-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}\.dump$`)
var databasePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)
var dumpVersionPattern = regexp.MustCompile(`^pg_dump \(PostgreSQL\) (16\.[0-9]{1,3})(?:[^\r\n]*)\n?$`)
var normalizedVersionPattern = regexp.MustCompile(`^16\.(0|[1-9][0-9]{0,2})$`)

type Config struct {
	Directory, RuntimeDirectory           string
	DeploymentFingerprint                 string
	Host, Database, PasswordFile, SSLMode string
	Port                                  uint16
	Timeout                               time.Duration
	MaxBytes                              int64
	dumpBinary                            string
}

type Receipt struct {
	Archive     string    `json:"archive"`
	SHA256      string    `json:"sha256"`
	Bytes       int64     `json:"bytes"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Role        string    `json:"role"`
	DumpVersion string    `json:"dump_version"`
}

type State struct {
	Version               int       `json:"version"`
	DeploymentFingerprint string    `json:"deployment_fingerprint"`
	AttemptStartedAt      time.Time `json:"attempt_started_at"`
	AttemptDeadline       time.Time `json:"attempt_deadline"`
	Outcome               string    `json:"outcome"`
	LatestSuccess         *Receipt  `json:"latest_success"`
}

type Status struct {
	Receipt    Receipt
	InProgress bool
}

func validReceipt(receipt Receipt) bool {
	return archivePattern.MatchString(receipt.Archive) && digestPattern.MatchString(receipt.SHA256) && receipt.Bytes >= 5 && receipt.Bytes <= 1<<40 && receipt.Role == "nethub_backup" && normalizedVersionPattern.MatchString(receipt.DumpVersion) && !receipt.StartedAt.IsZero() && !receipt.CompletedAt.Before(receipt.StartedAt) && receipt.CompletedAt.Sub(receipt.StartedAt) <= 30*time.Minute && receipt.Archive[7:23] == receipt.StartedAt.UTC().Format("20060102T150405Z")
}

func validState(state State) bool {
	if state.Version != 1 || !digestPattern.MatchString(state.DeploymentFingerprint) || state.AttemptStartedAt.IsZero() || !state.AttemptDeadline.After(state.AttemptStartedAt) || state.AttemptDeadline.Sub(state.AttemptStartedAt) > 30*time.Minute {
		return false
	}
	if state.Outcome != "running" && state.Outcome != "succeeded" && state.Outcome != "failed" {
		return false
	}
	if state.LatestSuccess == nil {
		return state.Outcome != "succeeded"
	}
	receipt := *state.LatestSuccess
	if !validReceipt(receipt) {
		return false
	}
	if state.Outcome == "succeeded" {
		return receipt.StartedAt.Equal(state.AttemptStartedAt) && !receipt.CompletedAt.After(state.AttemptDeadline)
	}
	return !receipt.CompletedAt.After(state.AttemptStartedAt)
}
