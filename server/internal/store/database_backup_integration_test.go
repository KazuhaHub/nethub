package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/dbbackup"
)

func testRestrictedBackup(t *testing.T, parent context.Context, backup *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	base := t.TempDir()
	data, runtime := filepath.Join(base, "archives"), filepath.Join(base, "runtime")
	for _, directory := range []string{data, runtime} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	config := dbbackup.Config{Directory: data, RuntimeDirectory: runtime, DeploymentFingerprint: strings.Repeat("a", 64), Host: "127.0.0.1", Database: "nethub", PasswordFile: "/run/secrets/pg_nethub_backup", SSLMode: "disable", Port: 5432, Timeout: 10 * time.Second, MaxBytes: 64 << 20}
	var sourceDevices int
	if err := backup.QueryRowContext(ctx, `SELECT count(*) FROM devices`).Scan(&sourceDevices); err != nil || sourceDevices < 3 {
		t.Fatalf("backup cannot see forced-RLS fixture rows: %d %v", sourceDevices, err)
	}
	receipt, err := dbbackup.Run(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := dbbackup.Verify(ctx, data, config.DeploymentFingerprint, time.Hour)
	if err != nil || verified.Receipt != receipt {
		t.Fatalf("actual dump verification: %+v %v", verified, err)
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	restored := "nethub_backup_restore_" + hex.EncodeToString(suffix[:])
	psql := func(commandCtx context.Context, database, query string) ([]byte, error) {
		command := exec.CommandContext(commandCtx, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database, "-Atqc", query)
		command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
		return command.Output()
	}
	if _, err := psql(ctx, "postgres", "CREATE DATABASE "+restored); err != nil {
		t.Fatal("create owned restore fixture failed")
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := psql(cleanupCtx, "postgres", "DROP DATABASE "+restored+" WITH (FORCE)"); err != nil {
			t.Error("owned restore database cleanup failed")
		}
	})
	command := exec.CommandContext(ctx, "pg_restore", "--exit-on-error", "--no-owner", "--no-acl", "-U", "postgres", "-d", restored, filepath.Join(data, receipt.Archive))
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	if err := command.Run(); err != nil {
		t.Fatal("actual custom archive restore failed")
	}
	count, err := psql(ctx, restored, "SELECT count(*) FROM devices")
	if err != nil || strings.TrimSpace(string(count)) != strconv.Itoa(sourceDevices) {
		t.Fatal("restored device rows differ from the forced-RLS source")
	}
	if _, err := psql(ctx, "nethub", "ALTER ROLE nethub_backup NOBYPASSRLS"); err != nil {
		t.Fatal("owned backup role perturbation failed")
	}
	restoreRole := func() error { _, err := psql(ctx, "nethub", "ALTER ROLE nethub_backup BYPASSRLS"); return err }
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := psql(cleanupCtx, "nethub", "ALTER ROLE nethub_backup BYPASSRLS"); err != nil {
			t.Error("backup role restoration failed")
		}
	})
	if _, err := dbbackup.Run(ctx, config); !errors.Is(err, dbbackup.ErrDump) {
		t.Fatalf("forced-RLS dump without bypass: %v", err)
	}
	if _, err := dbbackup.Verify(ctx, data, config.DeploymentFingerprint, time.Hour); !errors.Is(err, dbbackup.ErrLastAttempt) {
		t.Fatalf("failed actual dump masked by old success: %v", err)
	}
	if _, err := os.Stat(filepath.Join(data, receipt.Archive)); err != nil {
		t.Fatal("previous successful archive lost after failed dump")
	}
	if err := restoreRole(); err != nil {
		t.Fatal("backup role recovery failed")
	}
	if _, err := dbbackup.Run(ctx, config); err != nil {
		t.Fatalf("actual dump recovery: %v", err)
	}
	if _, err := dbbackup.Verify(ctx, data, config.DeploymentFingerprint, time.Hour); err != nil {
		t.Fatal(err)
	}
	t.Log("Actual restricted pg_dump custom archive restored all forced-RLS device rows; missing BYPASSRLS failed without losing the previous archive, and role restoration recovered verification")
}
