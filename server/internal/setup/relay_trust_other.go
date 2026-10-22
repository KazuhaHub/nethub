//go:build !linux

package setup

import "context"

func RunRelayTrust(context.Context, RelayTrustOptions) (RelayTrustResult, error) {
	return RelayTrustResult{}, ErrRelayTrust
}
