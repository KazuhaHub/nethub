package dbbackup

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWorkerHealthRequiresLiveSuccessfulCycle(t *testing.T) {
	config := syntheticConfig(t)
	producer(t, config, "printf PGDMPsynthetic-archive")
	receipt, err := Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := AcquireRuntime(config.RuntimeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if duplicate, err := AcquireRuntime(config.RuntimeDirectory); !errors.Is(err, ErrBusy) {
		if duplicate != nil {
			duplicate.Close()
		}
		t.Fatalf("duplicate runtime worker accepted: %v", err)
	}
	state := WorkerState{Version: 1, Outcome: "starting", AttemptStartedAt: time.Now().UTC(), AttemptDeadline: time.Now().UTC().Add(time.Minute)}
	if err := WriteWorkerState(config.RuntimeDirectory, state); err != nil {
		t.Fatal(err)
	}
	if err := CheckWorkerHealth(context.Background(), config.Directory, config.RuntimeDirectory, time.Hour); !errors.Is(err, ErrLastAttempt) {
		t.Fatalf("old archive hid startup phase: %v", err)
	}
	state.Outcome = "succeeded"
	state.DeploymentFingerprint = config.DeploymentFingerprint
	state.LastSuccessfulCycleAt = time.Now().UTC()
	if state.LastSuccessfulCycleAt.Before(receipt.CompletedAt) {
		t.Fatal("fixture clock moved backwards")
	}
	if err := WriteWorkerState(config.RuntimeDirectory, state); err != nil {
		t.Fatal(err)
	}
	if err := CheckWorkerHealth(context.Background(), config.Directory, config.RuntimeDirectory, time.Hour); err != nil {
		t.Fatal(err)
	}
	state.AttemptStartedAt = time.Now().UTC()
	state.AttemptDeadline = state.AttemptStartedAt.Add(time.Minute)
	state.Outcome = "running"
	if err := WriteWorkerState(config.RuntimeDirectory, state); err != nil {
		t.Fatal(err)
	}
	if err := CheckWorkerHealth(context.Background(), config.Directory, config.RuntimeDirectory, time.Hour); err != nil {
		t.Fatalf("bounded attempt with a recent healthy cycle refused: %v", err)
	}
	state.Outcome = "failed"
	if err := WriteWorkerState(config.RuntimeDirectory, state); err != nil {
		t.Fatal(err)
	}
	if err := CheckWorkerHealth(context.Background(), config.Directory, config.RuntimeDirectory, time.Hour); !errors.Is(err, ErrLastAttempt) {
		t.Fatalf("old archive hid caller failure: %v", err)
	}
	state.Outcome = "succeeded"
	state.LastSuccessfulCycleAt = time.Now().UTC()
	if err := WriteWorkerState(config.RuntimeDirectory, state); err != nil {
		t.Fatal(err)
	}
	guard.Close()
	if err := CheckWorkerHealth(context.Background(), config.Directory, config.RuntimeDirectory, time.Hour); !errors.Is(err, ErrLastAttempt) {
		t.Fatalf("released worker lock remained healthy: %v", err)
	}
}

func TestWorkerHealthRefusesOverdueAttempt(t *testing.T) {
	config := syntheticConfig(t)
	producer(t, config, "printf PGDMPsynthetic-archive")
	if _, err := Run(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	guard, err := AcquireRuntime(config.RuntimeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	now := time.Now().UTC()
	state := WorkerState{Version: 1, Outcome: "running", AttemptStartedAt: now.Add(-4 * time.Minute), AttemptDeadline: now.Add(-3 * time.Minute), LastSuccessfulCycleAt: now.Add(-5 * time.Minute), DeploymentFingerprint: config.DeploymentFingerprint}
	if err := WriteWorkerState(config.RuntimeDirectory, state); err != nil {
		t.Fatal(err)
	}
	if err := CheckWorkerHealth(context.Background(), config.Directory, config.RuntimeDirectory, time.Hour); !errors.Is(err, ErrLastAttempt) {
		t.Fatalf("fresh archive hid overdue worker: %v", err)
	}
}
