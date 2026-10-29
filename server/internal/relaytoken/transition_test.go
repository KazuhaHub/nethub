package relaytoken

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var privateFailure = errors.New("private candidate or host diagnostic must not escape")

type journalFixture struct {
	intent         *Intent
	state          *State
	failPhase      string
	persistFailure bool
	corruptIntent  bool
	corruptState   bool
}

func (j *journalFixture) ReadIntent(context.Context) (Intent, error) {
	if j.intent == nil {
		return Intent{}, ErrMissing
	}
	return *j.intent, nil
}

func (j *journalFixture) WriteIntent(_ context.Context, intent Intent) error {
	if j.intent != nil && *j.intent != intent {
		return privateFailure
	}
	j.intent = &intent
	if j.corruptIntent {
		j.intent.Snapshot.After = strings.Repeat("e", 64)
	}
	return nil
}

func (j *journalFixture) ReadState(context.Context) (State, error) {
	if j.state == nil {
		return State{}, ErrMissing
	}
	return *j.state, nil
}

func (j *journalFixture) WriteState(_ context.Context, state State) error {
	if j.failPhase == state.Phase {
		if j.persistFailure {
			j.state = &state
		}
		return privateFailure
	}
	j.state = &state
	if j.corruptState {
		j.state.IntentDigest = strings.Repeat("e", 64)
	}
	return nil
}

type hostFixture struct {
	t                *testing.T
	journal          *journalFixture
	snapshot         Snapshot
	prepare, publish int
	reload, verify   int
	physicalChanges  int
	applied          bool
	failAt           string
	afterPublish     func()
}

func (h *hostFixture) Prepare(context.Context, Request) (Snapshot, error) {
	h.prepare++
	return h.snapshot, nil
}

func (h *hostFixture) VerifySnapshot(_ context.Context, intent Intent) error {
	if intent.Snapshot != h.snapshot || h.failAt == "snapshot" {
		return privateFailure
	}
	return nil
}

func (h *hostFixture) Publish(_ context.Context, intent Intent) error {
	h.t.Helper()
	if h.journal.state == nil || h.journal.state.Phase != "publishing" || intent.Snapshot != h.snapshot {
		h.t.Fatal("publish ran without its durable original intent/phase")
	}
	h.publish++
	if !h.applied {
		h.physicalChanges++
		h.applied = true
	}
	if h.afterPublish != nil {
		h.afterPublish()
	}
	if h.failAt == "publish" {
		return privateFailure
	}
	return nil
}

func (h *hostFixture) Reload(context.Context, Intent) error {
	h.t.Helper()
	if h.journal.state == nil || h.journal.state.Phase != "reloading" || !h.applied {
		h.t.Fatal("reload ran before the replacement was published and journaled")
	}
	h.reload++
	if h.failAt == "reload" {
		return privateFailure
	}
	return nil
}

func (h *hostFixture) Verify(context.Context, Intent) error {
	h.verify++
	if h.failAt == "verify" || !h.applied {
		return privateFailure
	}
	return nil
}

func fixture(t *testing.T) (Transition, *journalFixture, *hostFixture) {
	t.Helper()
	j := &journalFixture{}
	h := &hostFixture{t: t, journal: j, snapshot: Snapshot{Digest: strings.Repeat("a", 64),
		Before: strings.Repeat("b", 64), After: strings.Repeat("c", 64)}}
	e := Transition{Request: Request{OperationID: "12345678-1234-4123-8123-123456789abc", Binding: strings.Repeat("d", 64)},
		Journal: j, Host: h, Now: func() time.Time { return time.Unix(1700000000, 0) }}
	return e, j, h
}

func TestCompletedRetryObservesWithoutRepublishing(t *testing.T) {
	e, _, h := fixture(t)
	for range 2 {
		state, err := e.Run(context.Background())
		if err != nil || state.Phase != "complete" {
			t.Fatal("replacement did not complete")
		}
	}
	if h.prepare != 1 || h.publish != 1 || h.physicalChanges != 1 || h.reload != 1 || h.verify != 2 {
		t.Fatal("completed retry mutated live state or skipped fresh observation")
	}
}

func TestLostEffectResponsesKeepTheSameCandidate(t *testing.T) {
	for _, phase := range []string{"publish", "reload", "verify"} {
		t.Run(phase, func(t *testing.T) {
			e, j, h := fixture(t)
			h.failAt = phase
			state, err := e.Run(context.Background())
			want := map[string]string{"publish": "publishing", "reload": "reloading", "verify": "verifying"}[phase]
			if !errors.Is(err, ErrTransition) || state.Phase != want || strings.Contains(err.Error(), "private") {
				t.Fatal("ambiguous effect did not retain a fixed recovery phase")
			}
			original := *j.intent
			h.failAt = ""
			state, err = e.Run(context.Background())
			if err != nil || state.Phase != "complete" || *j.intent != original || h.prepare != 1 || h.physicalChanges != 1 {
				t.Fatal("recovery generated or applied a different candidate")
			}
		})
	}
}

func TestLostJournalAcknowledgementRecoversObservedPhase(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		e, j, h := fixture(t)
		j.failPhase, j.persistFailure = "published", persisted
		if _, err := e.Run(context.Background()); !errors.Is(err, ErrTransition) || h.physicalChanges != 1 {
			t.Fatal("expected interruption after publication")
		}
		j.failPhase = ""
		if state, err := e.Run(context.Background()); err != nil || state.Phase != "complete" || h.prepare != 1 || h.physicalChanges != 1 {
			t.Fatal("lost journal acknowledgement replaced the original operation")
		}
	}
}

func TestCancellationAfterMutationRetainsRecoveryIntent(t *testing.T) {
	e, j, h := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.afterPublish = cancel
	if _, err := e.Run(ctx); !errors.Is(err, ErrTransition) || j.state.Phase != "publishing" || h.reload != 0 {
		t.Fatal("cancelled mutation did not retain its durable phase")
	}
	h.afterPublish = nil
	if _, err := e.Run(context.Background()); err != nil || h.physicalChanges != 1 || h.prepare != 1 {
		t.Fatal("cancelled operation did not resume the original candidate")
	}
}

func TestChangedRequestOrSnapshotCannotRebaseTheOperation(t *testing.T) {
	for _, change := range []string{"request", "snapshot", "orphan", "state"} {
		t.Run(change, func(t *testing.T) {
			e, j, h := fixture(t)
			h.failAt = "publish"
			if _, err := e.Run(context.Background()); err == nil {
				t.Fatal("expected retained interruption")
			}
			h.failAt = ""
			before := h.publish
			switch change {
			case "request":
				e.Request.Binding = strings.Repeat("e", 64)
			case "snapshot":
				h.snapshot.After = strings.Repeat("e", 64)
			case "orphan":
				j.intent = nil
			case "state":
				j.state.IntentDigest = strings.Repeat("e", 64)
			}
			if _, err := e.Run(context.Background()); !errors.Is(err, ErrTransition) || h.publish != before || h.reload != 0 {
				t.Fatal("changed recovery input reached a live mutation")
			}
		})
	}
}

func TestUnconfirmedJournalWriteCannotReachLiveEffects(t *testing.T) {
	for _, intent := range []bool{false, true} {
		e, j, h := fixture(t)
		j.corruptIntent, j.corruptState = intent, !intent
		if _, err := e.Run(context.Background()); !errors.Is(err, ErrTransition) || h.publish != 0 || h.reload != 0 {
			t.Fatal("an unconfirmed intent or state write reached the live deployment")
		}
	}
}
