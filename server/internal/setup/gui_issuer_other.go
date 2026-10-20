//go:build !linux

package setup

import (
	"context"
	"os"
)

type GUIIssuerResult struct {
	State string `json:"state"`
	Steps int    `json:"steps"`
}

func guiRootFile(os.FileInfo) bool { return false }
func RunGUIIssuer(context.Context, GUIIssuerOptions) (GUIIssuerResult, error) {
	return GUIIssuerResult{}, ErrGUIIssuer
}
