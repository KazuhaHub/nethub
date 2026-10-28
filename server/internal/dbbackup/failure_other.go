//go:build !linux

package dbbackup

import (
	"context"
	"time"
)

func RecordFailedAttempt(context.Context, string, time.Time, time.Duration) error {
	return ErrUnavailable
}
