//go:build !linux

package setup

import "context"

func RunRelayTokenCommand(context.Context, RelayTokenCommandOptions) (RelayTokenCommandResult, error) {
	return RelayTokenCommandResult{}, ErrRelayTokenCommand
}
