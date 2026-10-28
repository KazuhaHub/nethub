//go:build !linux

package dbbackup

import (
	"context"
	"time"
)

func Prune(context.Context, string, string, time.Duration) (int, error) {
	return 0, ErrUnavailable
}
