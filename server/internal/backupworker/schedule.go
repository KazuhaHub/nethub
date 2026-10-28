package backupworker

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/dbbackup"
)

const DailyInterval = 24 * time.Hour
const RetryInterval = time.Hour

type Reporter func(Result, error)

func begin(config Config) (io.Closer, dbbackup.WorkerState, error) {
	var state dbbackup.WorkerState
	if err := Validate(config); err != nil {
		return nil, state, err
	}
	guard, err := dbbackup.AcquireRuntime(config.Backup.RuntimeDirectory)
	if err != nil {
		if errors.Is(err, dbbackup.ErrBusy) {
			return nil, state, dbbackup.ErrBusy
		}
		return nil, state, ErrStorage
	}
	now := time.Now().UTC()
	state = dbbackup.WorkerState{Version: 1, Outcome: "starting", AttemptStartedAt: now, AttemptDeadline: now.Add(config.Backup.Timeout)}
	if dbbackup.WriteWorkerState(config.Backup.RuntimeDirectory, state) != nil {
		guard.Close()
		return nil, state, ErrHealth
	}
	return guard, state, nil
}

// Once runs a maintenance backup without leaving a daemon behind. Archive
// verification remains available after the runtime lock is released.
func Once(ctx context.Context, config Config) (Result, error) {
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	guard, initial, err := begin(config)
	if err != nil {
		return Result{}, err
	}
	defer guard.Close()
	return Attempt(ctx, config, initial)
}

// Serve starts immediately, then waits a day after success or an hour after a
// failed attempt. A new process always starts unhealthy until its own cycle passes.
func Serve(ctx context.Context, config Config, report Reporter) error {
	return serve(ctx, config, report, Attempt, wait)
}

func serve(ctx context.Context, config Config, report Reporter, attempt func(context.Context, Config, dbbackup.WorkerState) (Result, error), pause func(context.Context, time.Duration) error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	guard, previous, err := begin(config)
	if err != nil {
		return err
	}
	defer guard.Close()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		result, err := attempt(ctx, config, previous)
		if report != nil {
			report(result, err)
		}
		if errors.Is(err, ErrHealth) || errors.Is(err, ErrOptions) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		previous = result.State
		delay := DailyInterval
		if err != nil {
			delay = RetryInterval
		}
		if err := pause(ctx, delay); err != nil {
			return err
		}
	}
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
