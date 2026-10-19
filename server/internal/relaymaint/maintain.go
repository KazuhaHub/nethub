// Package relaymaint runs a durable, single-operation relay renewal lifecycle.
package relaymaint

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaycert"
)

var ErrMaintenance = errors.New("relay certificate maintenance failed")

type State struct {
	Version              int                   `json:"version"`
	Phase                string                `json:"phase"`
	LastGood             string                `json:"last_good,omitempty"`
	Original             string                `json:"original,omitempty"`
	Candidate            string                `json:"candidate,omitempty"`
	Attempts             int                   `json:"attempts"`
	NextAttempt          time.Time             `json:"next_attempt,omitzero"`
	ErrorCode            string                `json:"error_code,omitempty"`
	AppliedAt            time.Time             `json:"applied_at,omitzero"`
	RecoveryMilliseconds int64                 `json:"recovery_milliseconds"`
	RecoveryKnown        bool                  `json:"recovery_known"`
	Assessment           *relaycert.Assessment `json:"assessment,omitempty"`
}

func (s State) validate() error {
	if s.Version != 1 || s.Attempts < 0 || s.Attempts > 3 || s.RecoveryMilliseconds < 0 {
		return ErrState
	}
	for _, id := range []string{s.LastGood, s.Original, s.Candidate} {
		if id != "" && !generationName.MatchString(id) {
			return ErrState
		}
	}
	switch s.Phase {
	case "idle":
		if s.Candidate != "" || s.Attempts != 0 || !s.NextAttempt.IsZero() {
			return ErrState
		}
	case "issued", "applying", "rollback", "waiting", "exhausted", "recovery-failed":
		if s.Candidate == "" || s.Original == "" {
			return ErrState
		}
	default:
		return ErrState
	}
	if (s.Phase == "applying" || s.Phase == "rollback" || s.Phase == "recovery-failed") && s.Attempts == 0 {
		return ErrState
	}
	if s.Phase == "waiting" && (s.Attempts == 0 || s.Attempts == 3 || s.NextAttempt.IsZero()) {
		return ErrState
	}
	if s.Phase != "waiting" && !s.NextAttempt.IsZero() {
		return ErrState
	}
	if s.Phase == "issued" && s.Attempts == 3 {
		return ErrState
	}
	switch s.ErrorCode {
	case "", "service_stopped", "authority_expired", "authority_rotation_required", "observation_failed", "current_invalid", "issuance_failed", "apply_failed", "rollback_failed", "candidate_invalid", "authority_due", "interrupted":
	default:
		return ErrState
	}
	return nil
}

// Service is implemented by the protected host adapter. Publish changes only
// leaf/key files; Restart targets only the already-authorized frps service.
type Service interface {
	Running(context.Context) (bool, error)
	Current() ([]byte, []byte, error)
	Publish([]byte, []byte) error
	Restart(context.Context) error
	Observe(context.Context) (string, error)
}

type Engine struct {
	Directory string
	Name      string
	CA, CAKey []byte           `json:"-"`
	Service   Service          `json:"-"`
	Now       func() time.Time `json:"-"`
}

func (e Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e Engine) verify(ctx context.Context, id string) error {
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for {
		observed, err := e.Service.Observe(bounded)
		if err == nil && observed == id {
			return nil
		}
		select {
		case <-bounded.Done():
			return ErrMaintenance
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (e Engine) apply(ctx context.Context, cert, key []byte, id string) error {
	if relaycert.Check(e.CA, cert, key, e.Name, e.now()) != nil {
		return ErrMaintenance
	}
	if e.Service.Publish(cert, key) != nil {
		return ErrMaintenance
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	err := e.Service.Restart(bounded)
	cancel()
	if err != nil {
		return ErrMaintenance
	}
	return e.verify(ctx, id)
}

// Run holds an OS file lease through issuance/application/verification. Retry is
// an explicit host-operator request and reuses the persisted issued generation.
func (e Engine) Run(ctx context.Context, retry bool) (State, error) {
	s, err := openStore(filepath.Join(e.Directory, "secrets", "issuer", "maintenance"))
	if err != nil {
		return State{}, err
	}
	defer s.close()
	state, err := s.load()
	if err != nil {
		return State{}, err
	}
	fail := func(code string) (State, error) {
		state.ErrorCode = code
		if s.save(state) != nil {
			return state, ErrState
		}
		return state, ErrMaintenance
	}
	id := state.LastGood
	if id == "" {
		id = state.Original
	}
	if id != "" {
		cert, key, err := s.generation(id)
		if err != nil {
			return state, ErrState
		}
		a, err := relaycert.Assess(e.CA, cert, key, e.Name, e.now())
		if err != nil {
			return fail("current_invalid")
		}
		state.Assessment = &a
		if a.AuthorityExpired {
			return fail("authority_expired")
		}
		if s.save(state) != nil {
			return state, ErrState
		}
	}
	if retry && (state.Phase == "exhausted" || state.Phase == "recovery-failed") {
		state.Phase = "issued"
		state.Attempts = 0
		state.NextAttempt = time.Time{}
		state.ErrorCode = ""
		if s.save(state) != nil {
			return state, ErrState
		}
	}
	if state.Phase == "exhausted" || state.Phase == "recovery-failed" {
		return state, ErrMaintenance
	}
	if retry && state.Phase == "waiting" {
		state.Phase = "issued"
		state.NextAttempt = time.Time{}
		state.ErrorCode = ""
		if s.save(state) != nil {
			return state, ErrState
		}
	}
	running, err := e.Service.Running(ctx)
	if err != nil {
		return fail("observation_failed")
	}
	if !running && state.Phase != "applying" && state.Phase != "rollback" && !(retry && state.Candidate != "") {
		return fail("service_stopped")
	}
	if state.Phase == "waiting" && e.now().Before(state.NextAttempt) {
		return state, nil
	}
	if state.Phase == "idle" {
		cert, key, err := e.Service.Current()
		if err != nil {
			return fail("current_invalid")
		}
		a, err := relaycert.Assess(e.CA, cert, key, e.Name, e.now())
		if err != nil {
			return fail("current_invalid")
		}
		state.Assessment = &a
		if a.AuthorityExpired {
			return fail("authority_expired")
		}
		if !a.Expired {
			observed, err := e.Service.Observe(ctx)
			if err != nil || observed != a.Fingerprint {
				return fail("observation_failed")
			}
			id, err := s.put(cert, key)
			if err != nil {
				return state, err
			}
			state.LastGood = id
		}
		state.ErrorCode = ""
		if a.AuthorityDue {
			state.ErrorCode = "authority_due"
		}
		if !missing(filepath.Join(s.root, "pending")) {
			candidate, key, err := s.pair("pending")
			if err != nil {
				return state, err
			}
			id, err := materialID(candidate, key)
			if err != nil {
				return state, err
			}
			if id == state.LastGood && removePending(s) != nil {
				return state, ErrState
			}
		}
		if !a.Due {
			return state, s.save(state)
		}
		if !a.CanExtend {
			return fail("authority_rotation_required")
		}
		original, err := s.put(cert, key)
		if err != nil {
			return state, err
		}
		state.Original = original
		// A complete pending generation is reused after a crash between its durable
		// write and the issued journal transition.
		candidate, keyCandidate, err := e.pendingCandidate(s)
		if err != nil {
			return state, err
		}
		if candidate == nil {
			issued, err := relaycert.Renew(e.CA, e.CAKey, e.Name, e.now())
			if err != nil {
				return fail("issuance_failed")
			}
			candidate, keyCandidate = issued.Certificate, issued.Key
			if s.putPair("pending", candidate, keyCandidate) != nil {
				return state, ErrState
			}
		}
		id, err := s.put(candidate, keyCandidate)
		if err != nil {
			return state, err
		}
		state.Candidate = id
		state.Phase = "issued"
		state.Attempts = 0
		state.ErrorCode = ""
		if s.save(state) != nil {
			return state, ErrState
		}
	}
	if state.Phase == "rollback" {
		return e.rollback(ctx, s, state)
	}
	cert, key, err := s.generation(state.Candidate)
	if err != nil {
		return state, err
	}
	if relaycert.Check(e.CA, cert, key, e.Name, e.now()) != nil {
		state.Phase = "exhausted"
		state.NextAttempt = time.Time{}
		return fail("candidate_invalid")
	}
	if state.Phase == "applying" {
		current, currentKey, err := e.Service.Current()
		if err == nil {
			id, err := materialID(current, currentKey)
			if err == nil && id == state.Candidate {
				observed, err := e.Service.Observe(ctx)
				if err == nil && observed == state.Candidate {
					return e.complete(s, state, cert, key, -1)
				}
			}
		}
	}
	// An interrupted final attempt must recover last-good instead of spending
	// an unbounded extra attempt after a process crash.
	if state.Attempts >= 3 {
		state.Phase = "rollback"
		if s.save(state) != nil {
			return state, ErrState
		}
		return e.rollback(ctx, s, state)
	}
	if ctx.Err() != nil {
		return fail("interrupted")
	}
	state.Phase = "applying"
	state.Attempts++
	state.NextAttempt = time.Time{}
	if s.save(state) != nil {
		return state, ErrState
	}
	started := time.Now()
	if e.apply(ctx, cert, key, state.Candidate) != nil {
		state.Phase = "rollback"
		state.ErrorCode = "apply_failed"
		if s.save(state) != nil {
			return state, ErrState
		}
		return e.rollback(ctx, s, state)
	}
	return e.complete(s, state, cert, key, time.Since(started).Milliseconds())
}

func (e Engine) complete(s *store, state State, cert, key []byte, milliseconds int64) (State, error) {
	state.LastGood = state.Candidate
	state.Candidate = ""
	state.Phase = "idle"
	state.Attempts = 0
	state.NextAttempt = time.Time{}
	state.ErrorCode = ""
	state.AppliedAt = e.now()
	state.RecoveryKnown = milliseconds >= 0
	state.RecoveryMilliseconds = milliseconds
	if !state.RecoveryKnown {
		state.RecoveryMilliseconds = 0
	}
	a, err := relaycert.Assess(e.CA, cert, key, e.Name, e.now())
	if err != nil {
		return state, ErrState
	}
	state.Assessment = &a
	if s.save(state) != nil {
		return state, ErrState
	}
	if removePending(s) != nil {
		return state, ErrState
	}
	return state, nil
}

func (e Engine) pendingCandidate(s *store) ([]byte, []byte, error) {
	if missing(filepath.Join(s.root, "pending")) {
		return nil, nil, nil
	}
	cert, key, err := s.pair("pending")
	if err != nil {
		return nil, nil, ErrState
	}
	if _, err := relaycert.Assess(e.CA, cert, key, e.Name, e.now()); err != nil {
		return nil, nil, ErrState
	}
	return cert, key, nil
}

func (e Engine) rollback(ctx context.Context, s *store, state State) (State, error) {
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	cert, key, err := s.generation(state.LastGood)
	if err != nil || e.apply(bounded, cert, key, state.LastGood) != nil {
		state.Phase = "recovery-failed"
		state.ErrorCode = "rollback_failed"
		if s.save(state) != nil {
			return state, ErrState
		}
		return state, ErrMaintenance
	}
	state.Phase = "waiting"
	state.ErrorCode = "apply_failed"
	if state.Attempts >= 3 {
		state.Phase = "exhausted"
		state.NextAttempt = time.Time{}
	} else {
		state.NextAttempt = e.now().Add(time.Duration(state.Attempts*state.Attempts) * time.Minute)
	}
	if s.save(state) != nil {
		return state, ErrState
	}
	return state, ErrMaintenance
}
