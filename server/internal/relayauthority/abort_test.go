package relayauthority

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

type cancellingTrustFixture struct {
	*transitionTrustFixture
	cancellation *relaytrust.Cancellation
	denyBegin    bool
	loseCancel   bool
	loseBegin    bool
	cancels      int
}

func (f *cancellingTrustFixture) BeginSwitch(ctx context.Context, r relaytrust.SwitchRequest) (*relaytrust.Switch, error) {
	if f.denyBegin || f.cancellation != nil {
		f.begin++
		return nil, ErrTransition
	}
	result, err := f.transitionTrustFixture.BeginSwitch(ctx, r)
	if err == nil && f.loseBegin {
		f.loseBegin = false
		return nil, ErrTransition
	}
	return result, err
}

func (f *cancellingTrustFixture) ReadSwitch(_ context.Context, id string) (*relaytrust.Switch, error) {
	if f.state == nil || f.state.ID != id {
		return nil, ErrTransition
	}
	copy := *f.state
	return &copy, nil
}
func (f *cancellingTrustFixture) CancelSwitch(ctx context.Context, r relaytrust.SwitchRequest, intent string) (*relaytrust.Cancellation, error) {
	f.cancels++
	if f.state != nil {
		return nil, ErrTransition
	}
	if f.cancellation == nil {
		f.cancellation = &relaytrust.Cancellation{SwitchRequest: r, ServerName: "relay.example.test", IntentDigest: intent, CancelledAt: f.now}
	}
	if f.cancellation.SwitchRequest != r || f.cancellation.IntentDigest != intent {
		return nil, ErrTransition
	}
	if f.loseCancel {
		f.loseCancel = false
		return nil, ErrTransition
	}
	copy := *f.cancellation
	return &copy, nil
}

func TestPreparedAbortIsDurableAndCannotReenterBegin(t *testing.T) {
	e, h, db := transitionFixture(t)
	trust := &cancellingTrustFixture{transitionTrustFixture: db, denyBegin: true, loseCancel: true}
	e.Trust = trust
	state, err := e.Run(context.Background())
	if err == nil || state.Phase != "prepared" {
		t.Fatal("fixture did not retain refused preparation")
	}
	state, err = e.Abort(context.Background())
	if err == nil || state.Phase != "aborting" || trust.cancellation == nil || CheckNoPendingTransition(e.Directory) == nil {
		t.Fatal("lost cancellation reply cleared protection")
	}
	begins := trust.begin
	if _, err := e.Run(context.Background()); err == nil || trust.begin != begins {
		t.Fatal("aborting operation replayed Begin")
	}
	state, err = e.Abort(context.Background())
	if err != nil || state.Phase != "aborted" || state.Cancellation == nil || CheckNoPendingTransition(e.Directory) != nil || h.apply != 0 || h.restore != 0 {
		t.Fatal("verified cancellation did not reopen maintenance", err)
	}
	first := state
	state, err = e.Abort(context.Background())
	if err != nil || !state.UpdatedAt.Equal(first.UpdatedAt) || !state.Cancellation.CancelledAt.Equal(first.Cancellation.CancelledAt) {
		t.Fatal("abort retry changed original timestamps")
	}
	trust.denyBegin = false
	if _, err := e.Run(context.Background()); err == nil || trust.begin != begins || h.apply != 0 {
		t.Fatal("aborted operation replayed live writes")
	}
}

func TestAbortRefusesStartedOrChangedHostState(t *testing.T) {
	e, h, db := transitionFixture(t)
	trust := &cancellingTrustFixture{transitionTrustFixture: db}
	e.Trust = trust
	crashTransition(t, e, "host_applied")
	if _, err := e.Abort(context.Background()); err == nil || trust.cancels != 0 || db.state.Phase != "pending" {
		t.Fatal("started transition was cancelled")
	}
	e, h, db = transitionFixture(t)
	trust = &cancellingTrustFixture{transitionTrustFixture: db, denyBegin: true}
	e.Trust = trust
	if _, err := e.Run(context.Background()); err == nil {
		t.Fatal("fixture begin unexpectedly passed")
	}
	if writeTransitionFile(h.live, []byte("unexpected\n"), false) != nil {
		t.Fatal("changed host fixture")
	}
	if _, err := e.Abort(context.Background()); err == nil || trust.cancels != 0 {
		t.Fatal("changed original host state was cancelled")
	}
}

func TestAbortedGuardRequiresCorrelatedDatabaseReceipt(t *testing.T) {
	e, _, db := transitionFixture(t)
	trust := &cancellingTrustFixture{transitionTrustFixture: db, denyBegin: true}
	e.Trust = trust
	_, _ = e.Run(context.Background())
	state, err := e.Abort(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	path := e.Directory + "/authority-transitions/" + e.Request.ID + "/state.json"
	state.Cancellation.IntentDigest = strings.Repeat("f", 64)
	raw, _ := transitionJSON(state)
	if writeTransitionFile(path, raw, false) != nil {
		t.Fatal("corrupt receipt fixture")
	}
	if CheckNoPendingTransition(e.Directory) == nil {
		t.Fatal("uncorrelated abort receipt reopened maintenance")
	}
}

func TestAbortingRecoversPositivelyIdentifiedLostAdmission(t *testing.T) {
	e, h, db := transitionFixture(t)
	trust := &cancellingTrustFixture{transitionTrustFixture: db, loseBegin: true}
	e.Trust = trust
	state, err := e.Run(context.Background())
	if err == nil || state.Phase != "prepared" || db.state == nil || db.state.Phase != "pending" {
		t.Fatal("lost admission fixture did not retain real pending decision")
	}
	state, err = e.Abort(context.Background())
	if err == nil || state.Phase != "aborting" || trust.cancellation != nil {
		t.Fatal("pending admission was cancelled")
	}
	starts := db.begin
	state, err = e.Run(context.Background())
	if err != nil && !errors.Is(err, ErrTransition) || state.Phase != "rolled_back" || db.begin != starts || h.apply != 0 || h.restore != 1 || CheckNoPendingTransition(e.Directory) != nil {
		t.Fatal("positively identified pending admission did not recover without Begin", err)
	}
}
