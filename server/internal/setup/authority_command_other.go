//go:build !linux

package setup

import "context"

func RunRelayAuthorityCommand(context.Context, RelayAuthorityCommandOptions) (RelayAuthorityCommandResult, error) {
	return RelayAuthorityCommandResult{}, ErrRelayAuthority
}
