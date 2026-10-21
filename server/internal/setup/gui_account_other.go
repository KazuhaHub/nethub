//go:build !linux

package setup

import "context"

func RunGUIAccount(context.Context, GUIAccountOptions) (GUIAccountResult, error) {
	return GUIAccountResult{}, ErrGUIAccount
}
