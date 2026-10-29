package relayauthority

import (
	"context"
	"path/filepath"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

type transitionCanceller interface {
	CancelSwitch(context.Context, relaytrust.SwitchRequest, string) (*relaytrust.Cancellation, error)
}

// Abort cancels only a complete prepared operation whose original host files,
// backup, maintenance and actual served leaf still verify. It never restores or
// reloads services, and never treats a missing SQL row as cancellation. A pending
// or completed database switch is refused; use normal recovery for that history.
// Partial initialization remains protected for explicit inspection.
func (e Transition) Abort(ctx context.Context) (TransitionState, error) {
	var state TransitionState
	canceller, ok := e.Trust.(transitionCanceller)
	if !ok || ctx.Err() != nil || !e.Request.Valid() || e.Host == nil || !canonical(e.Directory) {
		return state, ErrTransition
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	lease, err := hostlease.Acquire(filepath.Join(e.Directory, "relay-operation.lock"))
	if err != nil {
		return state, err
	}
	defer lease.Close()
	if CheckNoPendingTokenTransition(e.Directory) != nil {
		return state, ErrTransition
	}
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
	var intent transitionIntent
	intentPath := filepath.Join(operation, "intent.json")
	statePath := filepath.Join(operation, "state.json")
	if readTransitionJSON(intentPath, &intent) != nil || intent.Version != 1 || intent.Deployment != e.Directory || intent.ServerName != e.ServerName || intent.Request != e.Request || !digestPattern.MatchString(intent.SnapshotDigest) || readTransitionJSON(statePath, &state) != nil || !validTransitionState(state, intent, e.now()) {
		return state, ErrTransition
	}
	if state.Phase != "prepared" && state.Phase != "aborting" && state.Phase != "aborted" {
		return state, ErrTransition
	}
	if syncTransitionFile(intentPath) != nil || syncTransitionFile(statePath) != nil {
		return state, ErrTransition
	}
	// A completed cancellation cannot re-enter Begin or write live state. Retry
	// rechecks the durable database decision, without requiring old live bytes
	// after ordinary maintenance has legitimately resumed.
	if state.Phase == "aborted" {
		receipt, err := canceller.CancelSwitch(ctx, e.Request, state.IntentDigest)
		if err != nil || !receipt.Valid(e.ServerName, e.now()) || receipt.SwitchRequest != e.Request || receipt.IntentDigest != state.IntentDigest || !receipt.CancelledAt.Equal(state.Cancellation.CancelledAt) {
			return state, ErrTransition
		}
		return state, nil
	}
	snapshot, err := e.Host.Snapshot(ctx, operation, e.Request)
	if err != nil || snapshot != intent.SnapshotDigest {
		return state, ErrTransition
	}
	verify := func() error {
		observed, err := e.Host.Verify(ctx, operation, e.Request, snapshot, "rolled_back")
		if err != nil || observed != e.Request.PreviousLeaf || ctx.Err() != nil {
			return ErrTransition
		}
		return nil
	}
	if verify() != nil {
		return state, ErrTransition
	}
	save := func(next TransitionState) error {
		if next.UpdatedAt.Before(state.UpdatedAt) || !validTransitionState(next, intent, e.now()) {
			return ErrTransition
		}
		raw, err := transitionJSON(next)
		if err != nil || writeTransitionFile(statePath, raw, false) != nil {
			return ErrTransition
		}
		state = next
		return nil
	}
	if state.Phase == "prepared" {
		next := state
		next.Phase = "aborting"
		next.UpdatedAt = e.now()
		if save(next) != nil {
			return state, ErrTransition
		}
	}
	receipt, err := canceller.CancelSwitch(ctx, e.Request, state.IntentDigest)
	if err != nil || !receipt.Valid(e.ServerName, e.now()) || receipt.SwitchRequest != e.Request || receipt.IntentDigest != state.IntentDigest {
		return state, ErrTransition
	}
	// Hold the shared lease and verify again after serialized cancellation before
	// reopening ordinary maintenance. An ambiguous response leaves aborting set.
	if verify() != nil {
		return state, ErrTransition
	}
	next := state
	next.Phase = "aborted"
	next.UpdatedAt = e.now()
	next.Cancellation = receipt
	if save(next) != nil {
		return state, ErrTransition
	}
	return state, nil
}
