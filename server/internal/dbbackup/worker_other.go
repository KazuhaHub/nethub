//go:build !linux

package dbbackup

import (
	"context"
	"io"
	"time"
)

func AcquireRuntime(string) (io.Closer, error)                               { return nil, ErrUnavailable }
func WriteWorkerState(string, WorkerState) error                             { return ErrUnavailable }
func CheckWorkerHealth(context.Context, string, string, time.Duration) error { return ErrUnavailable }
