package dbbackup

import (
	"context"
	"os"
	"time"
)

// RecordFailedAttempt records a caller's failed preflight or retention phase
// against existing private state. It never invents a deployment identity or
// replaces a newer attempt/success. A first attempt with no state stays unhealthy.
func RecordFailedAttempt(ctx context.Context, directory string, started time.Time, budget time.Duration) error {
	now := time.Now().UTC()
	if ctx.Err() != nil || !privateDirectory(directory) || started.IsZero() || started.After(now) || now.Sub(started) > 35*time.Minute || budget < time.Second || budget > 30*time.Minute {
		return ErrUnavailable
	}
	guard, err := lock(directory)
	if err != nil {
		return err
	}
	defer guard.Close()
	root, err := os.OpenRoot(directory)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Close()
	if _, err := root.Lstat(stateName); os.IsNotExist(err) {
		return ErrStale
	}
	previous, err := readState(root)
	if err != nil {
		return err
	}
	if previous.AttemptStartedAt.After(started) || previous.LatestSuccess != nil && previous.LatestSuccess.CompletedAt.After(started) {
		return ErrBusy
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	failed := State{Version: 1, DeploymentFingerprint: previous.DeploymentFingerprint, AttemptStartedAt: started.UTC(), AttemptDeadline: started.UTC().Add(budget), Outcome: "failed", LatestSuccess: previous.LatestSuccess}
	return writeState(root, failed)
}
