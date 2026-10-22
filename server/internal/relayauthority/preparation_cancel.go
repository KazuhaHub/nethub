package relayauthority

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

const preparationCancellationFile = "cancelled-preparation.json"

// CheckPreparationOpen refuses every cancellation marker, including malformed
// or unsafe markers. Staging and admission must not replay a cancelled ID.
func CheckPreparationOpen(operation string) error {
	if !canonical(operation) {
		return ErrTransition
	}
	if _, err := os.Lstat(filepath.Join(operation, preparationCancellationFile)); !os.IsNotExist(err) {
		return ErrTransition
	}
	return nil
}

type preparationCancellation struct {
	Intent transitionIntent `json:"intent"`
	State  TransitionState  `json:"state"`
}

type preparationVerifier interface {
	// VerifyPreparation checks the current original deployment, independent
	// backup, journal and actual original TLS without reading staged candidates.
	// Its digest must bind all original bytes, ownership and exact host options.
	VerifyPreparation(context.Context, string, relaytrust.SwitchRequest) (string, string, error)
}

func validPreparationCancellation(v preparationCancellation, directory, id string, now time.Time) bool {
	i := v.Intent
	return i.Version == 1 && i.Deployment == directory && i.ServerName != "" && i.Request.Valid() && i.Request.ID == id &&
		digestPattern.MatchString(i.SnapshotDigest) && v.State.Phase == "aborted" && validTransitionState(v.State, i, now)
}

// publishPreparationCancellation exposes only a complete synced receipt. An
// interrupted temporary write must never appear to be a terminal decision.
// The caller holds the shared lease; an existing marker is never overwritten.
func publishPreparationCancellation(path string, raw []byte) error {
	parent := filepath.Dir(path)
	if !canonical(parent) {
		return ErrTransition
	}
	if _, err := protected(parent, true); err != nil {
		return ErrTransition
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return ErrTransition
	}
	f, err := os.CreateTemp(parent, ".preparation-cancellation-*")
	if err != nil {
		return ErrTransition
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(temporary, path) != nil || syncDirectory(parent) != nil {
		return ErrTransition
	}
	return nil
}

// CancelPreparation resolves an interrupted preparation without completing or
// trusting its partial snapshots. Explicit original options are required. It
// verifies the complete current original host twice under the shared lease and
// records a correlated permanent SQL cancellation before reopening maintenance.
// No partial file is deleted, repaired, restored or used for activation.
func (e Transition) CancelPreparation(ctx context.Context) (TransitionState, error) {
	var state TransitionState
	canceller, canCancel := e.Trust.(transitionCanceller)
	verifier, canVerify := e.Host.(preparationVerifier)
	if !canCancel || !canVerify || ctx.Err() != nil || !e.Request.Valid() || e.ServerName == "" || !canonical(e.Directory) {
		return state, ErrTransition
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	lease, err := hostlease.Acquire(filepath.Join(e.Directory, "relay-operation.lock"))
	if err != nil {
		return state, err
	}
	defer lease.Close()
	root := filepath.Join(e.Directory, "authority-transitions")
	operation := filepath.Join(root, e.Request.ID)
	for _, path := range []string{root, operation} {
		if !canonical(path) {
			return state, ErrTransition
		}
		if _, err := protected(path, true); err != nil {
			return state, ErrTransition
		}
	}
	marker := filepath.Join(operation, preparationCancellationFile)
	if _, err := os.Lstat(marker); err == nil {
		var existing preparationCancellation
		if readTransitionJSON(marker, &existing) != nil || !validPreparationCancellation(existing, e.Directory, e.Request.ID, e.now()) || existing.Intent.Request != e.Request || existing.Intent.ServerName != e.ServerName {
			return state, ErrTransition
		}
		state = existing.State
		receipt, err := canceller.CancelSwitch(ctx, e.Request, state.IntentDigest)
		if err != nil || !receipt.Valid(e.ServerName, e.now()) || receipt.SwitchRequest != e.Request || receipt.IntentDigest != state.IntentDigest || !receipt.CancelledAt.Equal(state.Cancellation.CancelledAt) || syncTransitionFile(marker) != nil {
			return state, ErrTransition
		}
		return state, nil
	} else if !os.IsNotExist(err) {
		return state, ErrTransition
	}
	// Preserve incomplete/unreadable output, but never rebind an independently
	// readable canonical intent to a different operation or relay.
	var original transitionIntent
	if readTransitionJSON(filepath.Join(operation, "intent.json"), &original) == nil &&
		(original.Version != 1 || original.Deployment != e.Directory || original.ServerName != e.ServerName || original.Request != e.Request) {
		return state, ErrTransition
	}
	baseline, observed, err := verifier.VerifyPreparation(ctx, operation, e.Request)
	if err != nil || !digestPattern.MatchString(baseline) || observed != e.Request.PreviousLeaf {
		return state, ErrTransition
	}
	intent := transitionIntent{Version: 1, Deployment: e.Directory, ServerName: e.ServerName, Request: e.Request, SnapshotDigest: baseline}
	rawIntent, err := transitionJSON(intent)
	if err != nil {
		return state, ErrTransition
	}
	identity := digest(rawIntent)
	receipt, err := canceller.CancelSwitch(ctx, e.Request, identity)
	if err != nil || !receipt.Valid(e.ServerName, e.now()) || receipt.SwitchRequest != e.Request || receipt.IntentDigest != identity {
		return state, ErrTransition
	}
	// A lost SQL reply leaves the original unresolved journal protected. The
	// database tombstone itself prevents future Begin, even before this marker.
	verified, observed, err := verifier.VerifyPreparation(ctx, operation, e.Request)
	if err != nil || verified != baseline || observed != e.Request.PreviousLeaf || ctx.Err() != nil {
		return state, ErrTransition
	}
	state = TransitionState{Version: 1, IntentDigest: identity, Phase: "aborted", UpdatedAt: e.now(), Cancellation: receipt}
	record := preparationCancellation{Intent: intent, State: state}
	raw, err := transitionJSON(record)
	if err != nil || !validPreparationCancellation(record, e.Directory, e.Request.ID, e.now()) || publishPreparationCancellation(marker, raw) != nil {
		return state, ErrTransition
	}
	return state, nil
}
