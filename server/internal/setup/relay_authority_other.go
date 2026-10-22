//go:build !linux

package setup

import (
	"context"
)

func RunRelayAuthority(context.Context, RelayAuthorityOptions) (RelayAuthorityResult, error) {
	return RelayAuthorityResult{}, ErrRelayAuthority
}
