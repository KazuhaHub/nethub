package relayauthority

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

// These fixture bytes model the host adapter boundary, not actual certificates,
// manifests, backups, service restarts or independently observed TLS.
type transitionHostFixture struct {
	live                               string
	failApply, failRestore, failVerify bool
	apply, restore                     int
}

func (h *transitionHostFixture) Snapshot(ctx context.Context, root string, r relaytrust.SwitchRequest) (string, error) {
	for name, raw := range map[string][]byte{"before.fixture": []byte("before\n"), "after.fixture": []byte("after\n")} {
		path := filepath.Join(root, name)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			if writeTransitionFile(path, raw, true) != nil {
				return "", ErrTransition
			}
		}
		actual, err := read(path, 100)
		if err != nil || !bytes.Equal(actual, raw) {
			return "", ErrTransition
		}
	}
	return digest([]byte("before\nafter\n")), nil
}
func (h *transitionHostFixture) Apply(ctx context.Context, root string, r relaytrust.SwitchRequest, identity string) error {
	h.apply++
	if err := writeTransitionFile(h.live, []byte("after\n"), false); err != nil {
		return err
	}
	if h.failApply {
		return ErrTransition
	}
	return nil
}
func (h *transitionHostFixture) Restore(ctx context.Context, root string, r relaytrust.SwitchRequest, identity string) error {
	h.restore++
	if h.failRestore {
		return ErrTransition
	}
	return writeTransitionFile(h.live, []byte("before\n"), false)
}
func (h *transitionHostFixture) Verify(ctx context.Context, root string, r relaytrust.SwitchRequest, identity, phase string) (string, error) {
	raw, err := read(h.live, 100)
	expected := []byte("after\n")
	observed := r.NextLeaf
	if phase == "rolled_back" {
		expected = []byte("before\n")
		observed = r.PreviousLeaf
	}
	if err != nil || !bytes.Equal(raw, expected) || phase == "committed" && h.failVerify {
		return "", ErrTransition
	}
	return observed, nil
}

type transitionTrustFixture struct {
	state                 *relaytrust.Switch
	now                   time.Time
	loseBegin, loseFinish bool
	denyFinish            bool
	begin, finish         int
}

func (f *transitionTrustFixture) BeginSwitch(ctx context.Context, r relaytrust.SwitchRequest) (*relaytrust.Switch, error) {
	f.begin++
	if f.state == nil {
		f.state = &relaytrust.Switch{SwitchRequest: r, ServerName: "relay.example.test", Phase: "pending", CreatedAt: f.now}
	}
	if f.state.SwitchRequest != r {
		return nil, ErrTransition
	}
	if f.loseBegin {
		f.loseBegin = false
		return nil, ErrTransition
	}
	copy := *f.state
	return &copy, nil
}
func (f *transitionTrustFixture) FinishSwitch(ctx context.Context, r relaytrust.SwitchRequest, phase, observed string) (*relaytrust.Switch, error) {
	f.finish++
	if f.denyFinish {
		return nil, ErrTransition
	}
	expected := r.NextLeaf
	if phase == "rolled_back" {
		expected = r.PreviousLeaf
	}
	if f.state == nil || f.state.SwitchRequest != r || observed != expected || f.state.Phase != "pending" && f.state.Phase != phase {
		return nil, ErrTransition
	}
	if f.state.Phase == "pending" {
		f.state.Phase = phase
		f.state.FinishedAt = &f.now
		f.state.ObservedLeaf = &observed
	}
	if f.loseFinish {
		f.loseFinish = false
		return nil, ErrTransition
	}
	copy := *f.state
	return &copy, nil
}

func transitionFixture(t *testing.T) (Transition, *transitionHostFixture, *transitionTrustFixture) {
	t.Helper()
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private fixture")
	}
	now := time.Now().UTC().Truncate(time.Second)
	h := &transitionHostFixture{live: filepath.Join(root, "live.fixture")}
	if writeTransitionFile(h.live, []byte("before\n"), true) != nil {
		t.Fatal("initial state")
	}
	db := &transitionTrustFixture{now: now}
	e := Transition{Directory: root, ServerName: "relay.example.test", Host: h, Trust: db, Now: func() time.Time { return now }, Request: relaytrust.SwitchRequest{
		ID: "11111111-1111-4111-8111-111111111111", GenerationID: "22222222-2222-4222-8222-222222222222",
		PreviousRoot: strings.Repeat("a", 64), NextRoot: strings.Repeat("b", 64), PreviousLeaf: strings.Repeat("c", 64), NextLeaf: strings.Repeat("d", 64)}}
	return e, h, db
}

func crashTransition(t *testing.T, e Transition, point string) {
	t.Helper()
	e.checkpoint = func(at string) {
		if at == point {
			panic("fixture power loss")
		}
	}
	crashed := false
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered != "fixture power loss" {
					panic(recovered)
				}
				crashed = true
			}
		}()
		_, _ = e.Run(context.Background())
	}()
	if !crashed {
		t.Fatal("did not reach crash checkpoint", point)
	}
}

func TestTransitionRecoversEachDurableCrashBoundary(t *testing.T) {
	for _, point := range []string{"prepared_loaded", "fence_received", "applying", "host_applied", "committing", "terminal_received", "committed"} {
		t.Run(point, func(t *testing.T) {
			e, h, db := transitionFixture(t)
			crashTransition(t, e, point)
			// A new engine/host instance must use disk state, not the previous object's
			// in-memory phase, applied counter or successful verification.
			reopened := &transitionHostFixture{live: h.live}
			e.Host = reopened
			state, err := e.Run(context.Background())
			rollback := point == "applying" || point == "host_applied"
			expected := "committed"
			if rollback {
				expected = "rolled_back"
			}
			if state.Phase != expected || db.state.Phase != expected || err != nil && !rollback {
				t.Fatal("crash recovery", state.Phase, db.state.Phase, err)
			}
			if rollback && reopened.apply != 0 || !rollback && reopened.restore != 0 {
				t.Fatal("replayed wrong direction")
			}
			beforeApply, beforeRestore := reopened.apply, reopened.restore
			if state, err = e.Run(context.Background()); err != nil || state.Phase != expected || reopened.apply != beforeApply || reopened.restore != beforeRestore {
				t.Fatal("terminal retry mutated host", err)
			}
		})
	}
}

func TestTransitionLostRepliesNeverChooseOppositeDecision(t *testing.T) {
	for _, phase := range []string{"committed", "rolled_back"} {
		t.Run(phase, func(t *testing.T) {
			e, h, db := transitionFixture(t)
			db.loseBegin = true
			if _, err := e.Run(context.Background()); err == nil || db.state.Phase != "pending" || h.apply != 0 {
				t.Fatal("lost begin performed host writes")
			}
			db.loseFinish = true
			h.failApply = phase == "rolled_back"
			state, err := e.Run(context.Background())
			if err == nil || db.state.Phase != phase || state.Phase == phase {
				t.Fatal("lost terminal reply claimed local completion")
			}
			applied, restored := h.apply, h.restore
			state, err = e.Run(context.Background())
			if err != nil || state.Phase != phase || h.apply != applied || h.restore != restored {
				t.Fatal("lost terminal reply replayed host writes", err)
			}
		})
	}
}

func TestTransitionFailedRollbackRetainsFenceAndResumes(t *testing.T) {
	e, h, db := transitionFixture(t)
	h.failApply = true
	h.failRestore = true
	state, err := e.Run(context.Background())
	if err == nil || state.Phase != "rolling_back" || db.state.Phase != "pending" || db.finish != 0 {
		t.Fatal("failed rollback resolved database fence")
	}
	h.failRestore = false
	state, err = e.Run(context.Background())
	if err == nil || state.Phase != "rolled_back" || db.state.Phase != "rolled_back" || h.apply != 1 {
		t.Fatal("rollback recovery failed")
	}
}

func TestTransitionRecoversRollbackCrashBoundaries(t *testing.T) {
	for _, point := range []string{"rolling_back", "host_restored", "terminal_received", "rolled_back"} {
		t.Run(point, func(t *testing.T) {
			e, h, db := transitionFixture(t)
			h.failApply = true
			crashTransition(t, e, point)
			applied := h.apply
			state, err := e.Run(context.Background())
			if state.Phase != "rolled_back" || db.state.Phase != "rolled_back" || h.apply != applied || err != nil && db.state.FinishedAt == nil {
				t.Fatal("rollback crash recovery failed", err)
			}
		})
	}
}

func TestTransitionRefusesUnverifiedCommitAndUnrelatedTerminalReceipt(t *testing.T) {
	e, h, db := transitionFixture(t)
	h.failVerify = true
	state, err := e.Run(context.Background())
	if err == nil || state.Phase != "rolled_back" || db.state.Phase != "rolled_back" || h.restore != 1 {
		t.Fatal("unverified host committed")
	}
	e, h, db = transitionFixture(t)
	crashTransition(t, e, "fence_received")
	db.state.Phase = "committed"
	db.state.FinishedAt = &db.now
	db.state.ObservedLeaf = &e.Request.NextLeaf
	if _, err := e.Run(context.Background()); err == nil || h.apply != 0 || h.restore != 0 {
		t.Fatal("stale terminal receipt authorized host writes")
	}
}

func TestTransitionUnsafeJournalPathsPreserveOutsideFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("privileged host POSIX link and mode contract")
	}
	for _, kind := range []string{"symlink", "hardlink", "mode"} {
		t.Run(kind, func(t *testing.T) {
			e, _, db := transitionFixture(t)
			crashTransition(t, e, "prepared_loaded")
			path := filepath.Join(e.Directory, "authority-transitions", e.Request.ID, "state.json")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(e.Directory, "outside.fixture")
			if os.WriteFile(outside, original, 0600) != nil {
				t.Fatal("outside fixture")
			}
			if kind == "mode" {
				if os.Chmod(path, 0644) != nil {
					t.Fatal("mode fixture")
				}
			} else {
				if os.Remove(path) != nil {
					t.Fatal("link fixture")
				}
				if kind == "symlink" {
					err = os.Symlink(outside, path)
				} else {
					err = os.Link(outside, path)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := e.Run(context.Background()); err == nil || db.begin != 0 {
				t.Fatal("unsafe state reached database")
			}
			actual, err := os.ReadFile(outside)
			if err != nil || !bytes.Equal(actual, original) {
				t.Fatal("unsafe journal modified outside file")
			}
		})
	}
}

func TestTransitionCorruptJournalAndSnapshotCannotReachDatabase(t *testing.T) {
	for _, name := range []string{"intent.json", "state.json", "before.fixture"} {
		t.Run(name, func(t *testing.T) {
			e, _, db := transitionFixture(t)
			crashTransition(t, e, "prepared_loaded")
			path := filepath.Join(e.Directory, "authority-transitions", e.Request.ID, name)
			if os.WriteFile(path, []byte("{\"unknown\":true}\n"), 0600) != nil {
				t.Fatal("corrupt fixture")
			}
			calls := db.begin
			if _, err := e.Run(context.Background()); err == nil || db.begin != calls {
				t.Fatal("corrupt journal reached database")
			}
		})
	}
	e, _, db := transitionFixture(t)
	crashTransition(t, e, "prepared_loaded")
	e.Request.NextLeaf = strings.Repeat("e", 64)
	if _, err := e.Run(context.Background()); err == nil || db.begin != 0 {
		t.Fatal("rebound request reached database")
	}
}

func TestTransitionUsesSharedLeaseBeforeSnapshotOrDatabase(t *testing.T) {
	e, _, db := transitionFixture(t)
	lease, err := hostlease.Acquire(filepath.Join(e.Directory, "relay-operation.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if _, err := e.Run(context.Background()); !errors.Is(err, hostlease.ErrBusy) || db.begin != 0 {
		t.Fatal("ignored shared relay lease", err)
	}
	if _, err := os.Lstat(filepath.Join(e.Directory, "authority-transitions")); !os.IsNotExist(err) {
		t.Fatal("contending operation created snapshot")
	}
}

func TestTransitionMissingStateCannotRewindPendingHostWrites(t *testing.T) {
	e, h, db := transitionFixture(t)
	crashTransition(t, e, "host_applied")
	if os.Remove(filepath.Join(e.Directory, "authority-transitions", e.Request.ID, "state.json")) != nil {
		t.Fatal("remove state fixture")
	}
	calls := db.begin
	applied, restored := h.apply, h.restore
	if _, err := e.Run(context.Background()); err == nil || db.begin != calls || h.apply != applied || h.restore != restored || db.state.Phase != "pending" {
		t.Fatal("missing state rewound an interrupted host transition")
	}
}

func TestTransitionRefusesMalformedAdapterReceiptBeforeHostWrites(t *testing.T) {
	e, h, db := transitionFixture(t)
	db.state = &relaytrust.Switch{SwitchRequest: e.Request, ServerName: e.ServerName, Phase: "pending", CreatedAt: db.now, FinishedAt: &db.now}
	if _, err := e.Run(context.Background()); err == nil || h.apply != 0 || h.restore != 0 || db.finish != 0 {
		t.Fatal("malformed adapter receipt authorized host writes")
	}
}

func TestTransitionPendingCommitDecisionRequiresFreshVerification(t *testing.T) {
	e, h, db := transitionFixture(t)
	db.denyFinish = true
	state, err := e.Run(context.Background())
	if err == nil || state.Phase != "committing" || db.state.Phase != "pending" {
		t.Fatal("failed finish lost durable commit decision")
	}
	finished := db.finish
	db.denyFinish = false
	h.failVerify = true
	state, err = e.Run(context.Background())
	if err == nil || state.Phase != "committing" || db.state.Phase != "pending" || db.finish != finished || h.apply != 1 || h.restore != 0 {
		t.Fatal("unverified retry resolved or reversed commit")
	}
	h.failVerify = false
	state, err = e.Run(context.Background())
	if err != nil || state.Phase != "committed" || h.apply != 1 || h.restore != 0 {
		t.Fatal("pending commit recovery replayed host writes", err)
	}
}

func TestTransitionCancellationAfterFenceDoesNotStartHostWrites(t *testing.T) {
	e, h, db := transitionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.checkpoint = func(point string) {
		if point == "fence_received" {
			cancel()
		}
	}
	state, err := e.Run(ctx)
	if err == nil || state.Phase != "prepared" || db.state.Phase != "pending" || h.apply != 0 || h.restore != 0 {
		t.Fatal("cancellation after admission started host writes")
	}
	e.checkpoint = nil
	if state, err = e.Run(context.Background()); err != nil || state.Phase != "committed" {
		t.Fatal("canceled admission did not recover", err)
	}
}
