package relayauthority

import (
	"os"
	"path/filepath"
	"time"
)

// CheckNoPendingTransition is a durable admission guard for ordinary host
// maintenance. A released process lease does not mean an interrupted authority
// transition completed. Partial, malformed or nonterminal journals fail closed.
// Call again under the shared relay lease before mutating any active files.
func CheckNoPendingTransition(directory string) error {
	if !canonical(directory) || CheckNoPendingTokenTransition(directory) != nil {
		return ErrTransition
	}
	root := filepath.Join(directory, "authority-transitions")
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
		path := filepath.Join(root, entry.Name())
		if !canonical(path) {
			return ErrTransition
		}
		if _, err := protected(path, true); err != nil {
			return ErrTransition
		}
		marker := filepath.Join(path, preparationCancellationFile)
		if _, err := os.Lstat(marker); err == nil {
			var record preparationCancellation
			if readTransitionJSON(marker, &record) != nil || !validPreparationCancellation(record, directory, entry.Name(), time.Now()) || syncTransitionFile(marker) != nil {
				return ErrTransition
			}
			continue
		} else if !os.IsNotExist(err) {
			return ErrTransition
		}
		var intent transitionIntent
		var state TransitionState
		if readTransitionJSON(filepath.Join(path, "intent.json"), &intent) != nil || readTransitionJSON(filepath.Join(path, "state.json"), &state) != nil {
			return ErrTransition
		}
		if intent.Version != 1 || intent.Deployment != directory || !intent.Request.Valid() || intent.Request.ID != entry.Name() || intent.ServerName == "" || !digestPattern.MatchString(intent.SnapshotDigest) || !validTransitionState(state, intent, time.Now()) {
			return ErrTransition
		}
		if state.Phase != "committed" && state.Phase != "rolled_back" && state.Phase != "aborted" {
			return ErrTransition
		}
	}
	return nil
}
