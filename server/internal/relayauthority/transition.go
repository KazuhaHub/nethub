package relayauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

var ErrTransition = errors.New("relay authority transition requires verified host recovery")

// TransitionHost must preserve an immutable, independently backed-up before/after
// snapshot in the operation directory. Its digest binds all files, ownership,
// manifest, backup and maintenance-journal changes. Snapshot must sync its files
// before returning and revalidate the same snapshot on every call. Apply/Restore
// may replace only known before/after states and must preserve unrelated files.
// Verify independently checks those files and the actual CA/name/served leaf;
// returning a configured or expected fingerprint is not verification.
// Every callback must honor cancellation and bound external commands internally.
type TransitionHost interface {
	Snapshot(context.Context, string, relaytrust.SwitchRequest) (string, error)
	Apply(context.Context, string, relaytrust.SwitchRequest, string) error
	Restore(context.Context, string, relaytrust.SwitchRequest, string) error
	Verify(context.Context, string, relaytrust.SwitchRequest, string, string) (string, error)
}

type TransitionTrust interface {
	BeginSwitch(context.Context, relaytrust.SwitchRequest) (*relaytrust.Switch, error)
	FinishSwitch(context.Context, relaytrust.SwitchRequest, string, string) (*relaytrust.Switch, error)
}

type TransitionState struct {
	Version      int       `json:"version"`
	IntentDigest string    `json:"intent_sha256"`
	Phase        string    `json:"phase"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type transitionIntent struct {
	Version        int                      `json:"version"`
	Deployment     string                   `json:"deployment"`
	ServerName     string                   `json:"server_name"`
	Request        relaytrust.SwitchRequest `json:"request"`
	SnapshotDigest string                   `json:"snapshot_sha256"`
}

// Transition coordinates the host journal and database fence. A concrete host
// adapter must supply the protected snapshot/migration/TLS checks; this engine
// itself has no signer, service restart capability or public activation command.
type Transition struct {
	Directory  string
	ServerName string
	Request    relaytrust.SwitchRequest
	Host       TransitionHost
	Trust      TransitionTrust
	Now        func() time.Time
	checkpoint func(string)
}

func (e Transition) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func transitionJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 16383 {
		return nil, ErrTransition
	}
	return append(raw, '\n'), nil
}

func readTransitionJSON(path string, v any) error {
	raw, err := read(path, 16384)
	if err != nil || json.Unmarshal(raw, v) != nil {
		return ErrTransition
	}
	expected, err := transitionJSON(v)
	if err != nil || !bytes.Equal(raw, expected) {
		return ErrTransition
	}
	return nil
}

func syncTransitionFile(path string) error {
	before, err := protected(path, false)
	if err != nil {
		return ErrTransition
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return ErrTransition
	}
	opened, err := f.Stat()
	if err != nil || !owned(opened) || !os.SameFile(before, opened) {
		f.Close()
		return ErrTransition
	}
	err = f.Sync()
	closeErr := f.Close()
	after, statErr := os.Lstat(path)
	if err != nil || closeErr != nil || statErr != nil || !os.SameFile(before, after) || syncDirectory(filepath.Dir(path)) != nil {
		return ErrTransition
	}
	return nil
}

func writeTransitionFile(path string, raw []byte, exclusive bool) error {
	parent := filepath.Dir(path)
	if !canonical(parent) {
		return ErrTransition
	}
	if _, err := protected(parent, true); err != nil {
		return ErrTransition
	}
	if exclusive {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return ErrTransition
		}
		if err = f.Chmod(0600); err == nil {
			_, err = f.Write(raw)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil || syncDirectory(parent) != nil {
			return ErrTransition
		}
		return nil
	}
	if _, err := protected(path, false); err != nil {
		return ErrTransition
	}
	f, err := os.CreateTemp(parent, ".transition-*")
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

func transitionDirectory(path string) error {
	parent := filepath.Dir(path)
	if !canonical(parent) {
		return ErrTransition
	}
	if _, err := protected(parent, true); err != nil {
		return ErrTransition
	}
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return ErrTransition
	}
	if !canonical(path) {
		return ErrTransition
	}
	if _, err := protected(path, true); err != nil || syncDirectory(parent) != nil {
		return ErrTransition
	}
	return nil
}

func validTransitionPhase(phase string) bool {
	switch phase {
	case "prepared", "applying", "committing", "rolling_back", "committed", "rolled_back":
		return true
	}
	return false
}

// Run holds the shared relay lease through snapshot, admission, application,
// independent verification and terminal acknowledgement. After interruption in
// applying, recovery rolls back; after a durable committing decision it verifies
// the new state and retries commit. Ambiguous terminal replies never trigger the
// opposite decision. Pending protection never expires.
func (e Transition) Run(ctx context.Context) (TransitionState, error) {
	var state TransitionState
	if ctx.Err() != nil || !e.Request.Valid() || e.ServerName == "" || e.Host == nil || e.Trust == nil || !canonical(e.Directory) {
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
	if transitionDirectory(root) != nil {
		return state, ErrTransition
	}
	operation := filepath.Join(root, e.Request.ID)
	if transitionDirectory(operation) != nil {
		return state, ErrTransition
	}
	intentPath := filepath.Join(operation, "intent.json")
	statePath := filepath.Join(operation, "state.json")
	var intent transitionIntent
	_, intentErr := os.Lstat(intentPath)
	if intentErr == nil {
		if readTransitionJSON(intentPath, &intent) != nil || intent.Version != 1 || intent.Deployment != e.Directory || intent.ServerName != e.ServerName || intent.Request != e.Request || !digestPattern.MatchString(intent.SnapshotDigest) {
			return state, ErrTransition
		}
	} else if !os.IsNotExist(intentErr) {
		return state, ErrTransition
	}
	if intentErr != nil {
		if _, err := os.Lstat(statePath); !os.IsNotExist(err) {
			return state, ErrTransition
		}
	}
	// This callback may only create/revalidate operation-local immutable snapshots;
	// it must not mutate live host state or acquire a second relay operation lease.
	snapshot, err := e.Host.Snapshot(ctx, operation, e.Request)
	if err != nil || !digestPattern.MatchString(snapshot) {
		return state, ErrTransition
	}
	if intentErr == nil {
		if snapshot != intent.SnapshotDigest || syncTransitionFile(intentPath) != nil {
			return state, ErrTransition
		}
	} else {
		intent = transitionIntent{Version: 1, Deployment: e.Directory, ServerName: e.ServerName, Request: e.Request, SnapshotDigest: snapshot}
		raw, err := transitionJSON(intent)
		if err != nil {
			return state, ErrTransition
		}
		// The immutable intent is the initialization completion marker. Persist
		// prepared state first, so a missing state beside an existing intent can
		// never be mistaken for a fresh operation after live writes began.
		state = TransitionState{Version: 1, IntentDigest: digest(raw), Phase: "prepared", UpdatedAt: e.now()}
		encoded, err := transitionJSON(state)
		if err != nil || state.UpdatedAt.IsZero() || writeTransitionFile(statePath, encoded, true) != nil || writeTransitionFile(intentPath, raw, true) != nil {
			return state, ErrTransition
		}
	}
	raw, _ := transitionJSON(intent)
	identity := digest(raw)
	if readTransitionJSON(statePath, &state) != nil {
		return state, ErrTransition
	}
	if state.Version != 1 || state.IntentDigest != identity || !validTransitionPhase(state.Phase) || state.UpdatedAt.IsZero() || state.UpdatedAt.After(e.now().Add(5*time.Second)) || syncTransitionFile(statePath) != nil {
		return state, ErrTransition
	}
	checkpoint := func(point string) {
		if e.checkpoint != nil {
			e.checkpoint(point)
		}
	}
	save := func(phase string) error {
		next := state
		next.Phase = phase
		next.UpdatedAt = e.now()
		if next.UpdatedAt.IsZero() || next.UpdatedAt.Before(state.UpdatedAt) {
			return ErrTransition
		}
		encoded, err := transitionJSON(next)
		if err != nil || writeTransitionFile(statePath, encoded, false) != nil {
			return ErrTransition
		}
		state = next
		checkpoint(phase)
		return nil
	}
	checkpoint("prepared_loaded")
	if ctx.Err() != nil {
		return state, ErrTransition
	}
	receipt, err := e.Trust.BeginSwitch(ctx, e.Request)
	if err != nil || !receipt.Valid(e.ServerName, e.now()) || receipt.SwitchRequest != e.Request {
		return state, ErrTransition
	}
	checkpoint("fence_received")
	if ctx.Err() != nil {
		return state, ErrTransition
	}
	verify := func(phase string) (string, error) {
		expected := e.Request.NextLeaf
		if phase == "rolled_back" {
			expected = e.Request.PreviousLeaf
		}
		observed, err := e.Host.Verify(ctx, operation, e.Request, snapshot, phase)
		if err != nil || observed != expected {
			return "", ErrTransition
		}
		return observed, nil
	}
	finish := func(phase string) error {
		if ctx.Err() != nil {
			return ErrTransition
		}
		observed, err := verify(phase)
		if err != nil {
			return ErrTransition
		}
		accepted, err := e.Trust.FinishSwitch(ctx, e.Request, phase, observed)
		if err != nil || !accepted.Valid(e.ServerName, e.now()) || accepted.SwitchRequest != e.Request || accepted.Phase != phase || accepted.ObservedLeaf == nil || *accepted.ObservedLeaf != observed {
			return ErrTransition
		}
		checkpoint("terminal_received")
		return save(phase)
	}
	if receipt.Phase == "committed" || receipt.Phase == "rolled_back" {
		// Only a locally durable matching decision can adopt an already terminal
		// database receipt. A stale receipt must not authorize host writes.
		decision := "committing"
		if receipt.Phase == "rolled_back" {
			decision = "rolling_back"
		}
		if state.Phase != decision && state.Phase != receipt.Phase {
			return state, ErrTransition
		}
		if _, err := verify(receipt.Phase); err != nil {
			return state, ErrTransition
		}
		if state.Phase != receipt.Phase && save(receipt.Phase) != nil {
			return state, ErrTransition
		}
		return state, nil
	}
	if receipt.Phase != "pending" || state.Phase == "committed" || state.Phase == "rolled_back" {
		return state, ErrTransition
	}
	if state.Phase == "committing" {
		err := finish("committed")
		return state, err
	}
	if state.Phase == "prepared" {
		if save("applying") != nil {
			return state, ErrTransition
		}
		if err := e.Host.Apply(ctx, operation, e.Request, snapshot); err == nil {
			checkpoint("host_applied")
			if _, err := verify("committed"); err == nil {
				if save("committing") != nil {
					return state, ErrTransition
				}
				err := finish("committed")
				return state, err
			}
		}
	}
	if save("rolling_back") != nil {
		return state, ErrTransition
	}
	if e.Host.Restore(ctx, operation, e.Request, snapshot) != nil {
		return state, ErrTransition
	}
	checkpoint("host_restored")
	if finish("rolled_back") != nil {
		return state, ErrTransition
	}
	return state, ErrTransition
}
