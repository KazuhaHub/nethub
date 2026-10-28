package dbbackup

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestCallerFailurePreservesSuccessAndRefusesOutOfOrderFailure(t *testing.T) {
	config := syntheticConfig(t)
	producer(t, config, "printf PGDMPsynthetic-archive")
	if err := RecordFailedAttempt(context.Background(), config.Directory, time.Now().UTC(), time.Minute); !errors.Is(err, ErrStale) {
		t.Fatalf("first failure invented state: %v", err)
	}
	oldAttempt := time.Now().UTC().Add(-time.Second)
	receipt, err := Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	snapshotRoot, err := os.OpenRoot(config.Directory)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshotRoot.Close()
	baseline, err := readState(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := RecordFailedAttempt(context.Background(), config.Directory, oldAttempt, time.Minute); !errors.Is(err, ErrBusy) {
		t.Fatalf("older failure replaced newer success: %v", err)
	}
	if _, err := Verify(context.Background(), config.Directory, config.DeploymentFingerprint, time.Hour); err != nil {
		t.Fatalf("older failure damaged verification: %v", err)
	}
	if !recordedStateUnchanged(snapshotRoot, baseline) {
		t.Fatal("refused old failure changed the observed state")
	}
	if err := RecordFailedAttempt(context.Background(), config.Directory, time.Now().UTC(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if recordedStateUnchanged(snapshotRoot, baseline) {
		t.Fatal("new failure was invisible to the verification snapshot guard")
	}
	if _, err := Verify(context.Background(), config.Directory, config.DeploymentFingerprint, time.Hour); !errors.Is(err, ErrLastAttempt) {
		t.Fatalf("caller failure masked: %v", err)
	}
	root, err := os.OpenRoot(config.Directory)
	if err != nil {
		t.Fatal(err)
	}
	state, err := readState(root)
	root.Close()
	if err != nil || state.LatestSuccess == nil || *state.LatestSuccess != receipt || state.DeploymentFingerprint != config.DeploymentFingerprint {
		t.Fatal("caller failure changed retained archive or identity")
	}
	if _, err := Run(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), config.Directory, config.DeploymentFingerprint, time.Hour); err != nil {
		t.Fatal(err)
	}
}
