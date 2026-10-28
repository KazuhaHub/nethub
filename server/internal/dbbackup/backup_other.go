//go:build !linux

package dbbackup

import (
	"context"
	"time"
)

func Run(context.Context, Config) (Receipt, error) { return Receipt{}, ErrUnavailable }
func Verify(context.Context, string, string, time.Duration) (Status, error) {
	return Status{}, ErrUnavailable
}
func VerifyWithBudget(context.Context, string, string, time.Duration, time.Duration) (Status, error) {
	return Status{}, ErrUnavailable
}
func VerifyMetadata(context.Context, string, string, time.Duration) (Status, error) {
	return Status{}, ErrUnavailable
}
