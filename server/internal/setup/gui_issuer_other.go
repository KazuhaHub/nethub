//go:build !linux

package setup

import (
	"context"
	"os"
)

func guiRootFile(os.FileInfo) bool { return false }
func RunGUIIssuer(context.Context, GUIIssuerOptions) (GUIIssuerResult, error) {
	return GUIIssuerResult{}, ErrGUIIssuer
}
