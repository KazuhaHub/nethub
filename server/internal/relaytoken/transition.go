// Package relaytoken coordinates a protected host's shared-token replacement.
package relaytoken

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

var ErrTransition = errors.New("shared relay token replacement requires verified host recovery")
var ErrMissing = errors.New("shared relay token operation record is absent")

var operationID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Request binds one operation to the original deployment/service inspection.
// Binding is a digest, never a mutable live discovery result on resumption.
type Request struct {
	OperationID string `json:"operation_id"`
	Binding     string `json:"binding_sha256"`
}

type Snapshot struct {
	Digest string `json:"snapshot_sha256"`
	Before string `json:"previous_token_sha256"`
	After  string `json:"candidate_token_sha256"`
}

type Intent struct {
	Version  int      `json:"version"`
	Request  Request  `json:"request"`
	Snapshot Snapshot `json:"snapshot"`
}

type State struct {
	Version      int       `json:"version"`
	OperationID  string    `json:"operation_id"`
	IntentDigest string    `json:"intent_sha256"`
	Phase        string    `json:"phase"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (r Request) Valid() bool {
	return operationID.MatchString(r.OperationID) && digest.MatchString(r.Binding)
}

func (i Intent) Valid() bool {
	return i.Version == 1 && i.Request.Valid() && digest.MatchString(i.Snapshot.Digest) &&
		digest.MatchString(i.Snapshot.Before) && digest.MatchString(i.Snapshot.After) &&
		i.Snapshot.Before != i.Snapshot.After
}

func (i Intent) Digest() string {
	raw, _ := json.Marshal(i)
	value := sha256.Sum256(raw)
	return hex.EncodeToString(value[:])
}

// Journal must enforce protected paths, bounded canonical decoding and a single
// immutable intent. State writes require atomic replacement and directory fsync.
// ErrMissing means absent; malformed or partly published records are errors.
type Journal interface {
	ReadIntent(context.Context) (Intent, error)
	WriteIntent(context.Context, Intent) error
	ReadState(context.Context) (State, error)
	WriteState(context.Context, State) error
}

// Host owns the real file, backup and runtime boundary. Prepare may only create
// or validate immutable operation-local snapshots and an independent successor
// backup. It must reuse a retained candidate after interruption. VerifySnapshot
// rechecks that exact material on every call. Publish accepts only known before
// or after file states and never restores the compromised previous token.
// Reload affects only bound services. Verify must observe actual replacement
// admission and runtime recovery rather than return configured expectations.
// Callbacks must honor cancellation and bound external work internally.
type Host interface {
	Prepare(context.Context, Request) (Snapshot, error)
	VerifySnapshot(context.Context, Intent) error
	Publish(context.Context, Intent) error
	Reload(context.Context, Intent) error
	Verify(context.Context, Intent) error
}

// Transition assumes the concrete caller holds the shared host operation lease
// and has refused competing unresolved operations. This coordinator provides no
// filesystem privilege, service discovery, rollback or public HTTP entry point.
type Transition struct {
	Request Request
	Journal Journal
	Host    Host
	Now     func() time.Time
}

func (e Transition) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (s State) Valid(intent Intent) bool {
	if !intent.Valid() || s.Version != 1 || s.OperationID != intent.Request.OperationID || s.IntentDigest != intent.Digest() || s.UpdatedAt.IsZero() {
		return false
	}
	switch s.Phase {
	case "prepared", "publishing", "published", "reloading", "verifying", "complete":
		return true
	}
	return false
}

// Run resumes the original intent. Every external mutation has a durable phase
// before it, so a lost response retries an idempotent operation with the same
// candidate. Completion is independently verified again on later invocations;
// an old completed journal must never reapply material after a newer incident.
func (e Transition) Run(ctx context.Context) (State, error) {
	var state State
	if !e.Request.Valid() || e.Journal == nil || e.Host == nil || ctx.Err() != nil {
		return state, ErrTransition
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	intent, err := e.Journal.ReadIntent(bounded)
	if errors.Is(err, ErrMissing) {
		if _, stateErr := e.Journal.ReadState(bounded); !errors.Is(stateErr, ErrMissing) {
			return state, ErrTransition
		}
		snapshot, prepareErr := e.Host.Prepare(bounded, e.Request)
		intent = Intent{Version: 1, Request: e.Request, Snapshot: snapshot}
		if prepareErr != nil || !intent.Valid() || bounded.Err() != nil || e.Journal.WriteIntent(bounded, intent) != nil {
			return state, ErrTransition
		}
		observed, readErr := e.Journal.ReadIntent(bounded)
		if readErr != nil || observed != intent {
			return state, ErrTransition
		}
	} else if err != nil {
		return state, ErrTransition
	}
	if !intent.Valid() || intent.Request != e.Request {
		return state, ErrTransition
	}
	persist := func(next State) error {
		if bounded.Err() != nil || !next.Valid(intent) || e.Journal.WriteState(bounded, next) != nil {
			return ErrTransition
		}
		observed, readErr := e.Journal.ReadState(bounded)
		if readErr != nil || observed != next {
			return ErrTransition
		}
		state = observed
		return nil
	}
	state, err = e.Journal.ReadState(bounded)
	if errors.Is(err, ErrMissing) {
		next := State{Version: 1, OperationID: e.Request.OperationID, IntentDigest: intent.Digest(),
			Phase: "prepared", UpdatedAt: e.now()}
		if persist(next) != nil {
			return state, ErrTransition
		}
	} else if err != nil || !state.Valid(intent) {
		return state, ErrTransition
	}
	if bounded.Err() != nil || e.Host.VerifySnapshot(bounded, intent) != nil {
		return state, ErrTransition
	}
	setPhase := func(phase string) error {
		if bounded.Err() != nil {
			return ErrTransition
		}
		next := state
		next.Phase, next.UpdatedAt = phase, e.now()
		return persist(next)
	}
	if state.Phase == "prepared" || state.Phase == "publishing" {
		if setPhase("publishing") != nil || e.Host.Publish(bounded, intent) != nil || setPhase("published") != nil {
			return state, ErrTransition
		}
	}
	if state.Phase == "published" || state.Phase == "reloading" {
		if setPhase("reloading") != nil || e.Host.Reload(bounded, intent) != nil || setPhase("verifying") != nil {
			return state, ErrTransition
		}
	}
	if bounded.Err() != nil || e.Host.Verify(bounded, intent) != nil {
		return state, ErrTransition
	}
	if state.Phase != "complete" && setPhase("complete") != nil {
		return state, ErrTransition
	}
	return state, nil
}
