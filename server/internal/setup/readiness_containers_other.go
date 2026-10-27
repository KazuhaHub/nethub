//go:build !linux

package setup

import "context"

func CheckRuntimeContainers(context.Context, string, string, string) error {
	return ErrContainerReadiness
}
