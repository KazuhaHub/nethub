package relayauthority

import (
	"os"
	"path/filepath"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

// CheckNoPendingTokenTransition refuses ordinary host work after a token
// operation loses its process lease. Only a valid complete journal releases
// admission; partial preparation, malformed records and nonterminal phases never
// expire. Call again while holding relay-operation.lock before active effects.
func CheckNoPendingTokenTransition(directory string) error {
	if !canonical(directory) {
		return ErrTransition
	}
	root := filepath.Join(directory, "token-transitions")
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return nil
	}
	if !canonical(root) {
		return ErrTransition
	}
	if _, err := protected(root, true); err != nil {
		return ErrTransition
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > 4096 {
		return ErrTransition
	}
	for _, entry := range entries {
		operation := filepath.Join(root, entry.Name())
		if !canonical(operation) {
			return ErrTransition
		}
		if _, err := protected(operation, true); err != nil {
			return ErrTransition
		}
		var options struct {
			Directory       string             `json:"deployment"`
			SuccessorBackup string             `json:"successor_backup"`
			Request         relaytoken.Request `json:"request"`
		}
		var intent relaytoken.Intent
		var state relaytoken.State
		if readTransitionJSON(filepath.Join(operation, "options.json"), &options) != nil ||
			readTransitionJSON(filepath.Join(operation, "intent.json"), &intent) != nil ||
			readTransitionJSON(filepath.Join(operation, "state.json"), &state) != nil ||
			options.Directory != directory || !filepath.IsAbs(options.SuccessorBackup) ||
			filepath.Clean(options.SuccessorBackup) != options.SuccessorBackup ||
			!intent.Valid() || intent.Request.OperationID != entry.Name() || options.Request != intent.Request ||
			!state.Valid(intent) || state.Phase != "complete" {
			return ErrTransition
		}
	}
	return nil
}
