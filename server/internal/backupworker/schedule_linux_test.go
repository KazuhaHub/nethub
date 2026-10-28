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

func schedulerConfig(t *testing.T) Config {
	t.Helper()
	base := t.TempDir()
	runtime := filepath.Join(base, "runtime")
	if err := os.Mkdir(runtime, 0700); err != nil {
		t.Fatal(err)
	}
	return Config{Backup: dbbackup.Config{Directory: filepath.Join(base, "archives"), RuntimeDirectory: runtime, PasswordFile: filepath.Join(base, "password"), Host: "127.0.0.1", Port: 5432, Database: "nethub", SSLMode: "disable", Timeout: time.Minute, MaxBytes: 1024}, Retention: 24 * time.Hour}
}

// These scheduler-only fixtures test delays and exit behavior, not archive success.
func TestScheduleRetriesWithoutBusyLoopAndStopsOnCancellation(t *testing.T) {
	config := schedulerConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	var delays []time.Duration
	attempt := func(_ context.Context, _ Config, previous dbbackup.WorkerState) (Result, error) {
		calls++
		if calls == 1 {
			previous.Outcome = "failed"
			return Result{State: previous}, ErrDatabase
		}
		previous.Outcome = "succeeded"
		previous.AttemptStartedAt = time.Now().UTC()
		previous.AttemptDeadline = previous.AttemptStartedAt.Add(time.Minute)
		previous.LastSuccessfulCycleAt = previous.AttemptStartedAt
		previous.DeploymentFingerprint = strings.Repeat("a", 64)
		return Result{State: previous}, nil
	}
	pause := func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		if len(delays) == 2 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	if err := serve(ctx, config, nil, attempt, pause); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls != 2 || len(delays) != 2 || delays[0] != time.Hour || delays[1] != 24*time.Hour {
		t.Fatalf("unexpected schedule: calls=%d delays=%v", calls, delays)
	}
	guard, err := dbbackup.AcquireRuntime(config.Backup.RuntimeDirectory)
	if err != nil {
		t.Fatalf("canceled scheduler retained runtime lock: %v", err)
	}
	guard.Close()
}

func TestScheduleExitsWhenHealthCannotBePublished(t *testing.T) {
	config := schedulerConfig(t)
	waits := 0
	attempt := func(_ context.Context, _ Config, previous dbbackup.WorkerState) (Result, error) {
		return Result{State: previous}, ErrHealth
	}
	pause := func(context.Context, time.Duration) error { waits++; return nil }
	if err := serve(context.Background(), config, nil, attempt, pause); !errors.Is(err, ErrHealth) {
		t.Fatal(err)
	}
	if waits != 0 {
		t.Fatal("worker kept running with unavailable health state")
	}
}
