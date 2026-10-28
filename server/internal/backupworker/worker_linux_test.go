package backupworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/dbbackup"
)

func TestStorageFailureBecomesUnhealthyBeforeConnecting(t *testing.T) {
	base := t.TempDir()
	archives, runtime := filepath.Join(base, "archives"), filepath.Join(base, "runtime")
	for _, directory := range []string{archives, runtime} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	guard, err := dbbackup.AcquireRuntime(runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	config := Config{Backup: dbbackup.Config{Directory: archives, RuntimeDirectory: runtime, PasswordFile: filepath.Join(base, "missing-password"), Host: "127.0.0.1", Port: 1, Database: "nethub", SSLMode: "disable", Timeout: time.Second, MaxBytes: 1024}, Retention: 24 * time.Hour}
	previous := dbbackup.WorkerState{Version: 1, Outcome: "succeeded", LastSuccessfulCycleAt: time.Now().UTC().Add(-time.Hour), DeploymentFingerprint: strings.Repeat("a", 64)}
	result, err := Attempt(context.Background(), config, previous)
	if !errors.Is(err, ErrStorage) || result.State.Outcome != "failed" || !result.State.LastSuccessfulCycleAt.Equal(previous.LastSuccessfulCycleAt) {
		t.Fatalf("storage failure result: %v", err)
	}
	if err := dbbackup.CheckWorkerHealth(context.Background(), archives, runtime, 2*time.Hour); !errors.Is(err, dbbackup.ErrLastAttempt) {
		t.Fatalf("old success masked preflight failure: %v", err)
	}
}
