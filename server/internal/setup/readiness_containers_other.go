//go:build !linux

package setup

import "context"

func CheckRuntimeContainers(context.Context, string, string, string) error {
	return ErrContainerReadiness
}
func CheckRelayRuntimeContainers(context.Context, string, string, string) error {
	return ErrContainerReadiness
}
