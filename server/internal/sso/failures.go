package sso

import "errors"

type flowFailure struct{ reason string }

func (f *flowFailure) Error() string        { return ErrFlow.Error() }
func (f *flowFailure) Is(target error) bool { return target == ErrFlow }
func failedFlow(reason string) error        { return &flowFailure{reason: reason} }

// FailureReason exposes only fixed audit categories, never an upstream error.
func FailureReason(err error) string {
	var failure *flowFailure
	if errors.As(err, &failure) && ValidFailureReason(failure.reason) {
		return failure.reason
	}
	return "unavailable"
}

func ValidFailureReason(reason string) bool {
	switch reason {
	case "start", "callback", "unavailable", "provider_unavailable", "invitation_invalid", "discovery_failed", "state_unavailable", "state_invalid", "exchange_failed", "token_invalid", "nonce_invalid", "admission_denied", "admission_unavailable":
		return true
	default:
		return false
	}
}
