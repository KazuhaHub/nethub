package relayauthority

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

type preparationHostFixture struct {
	*transitionHostFixture
	checks       int
	failOriginal bool
	failSecond   bool
}

func (h *preparationHostFixture) VerifyPreparation(ctx context.Context, operation string, r relaytrust.SwitchRequest) (string, string, error) {
	h.checks++
	if h.failOriginal || h.failSecond && h.checks == 2 {
		return "", "", ErrTransition
	}
	observed, err := h.Verify(ctx, operation, r, "", "rolled_back")
	return digest([]byte("verified-original-baseline\n")), observed, err
}

func partialPreparationFixture(t *testing.T) (Transition, *preparationHostFixture, *cancellingTrustFixture, map[string][]byte) {
	t.Helper()
	e, original, db := transitionFixture(t)
	host := &preparationHostFixture{transitionHostFixture: original}
	trust := &cancellingTrustFixture{transitionTrustFixture: db, denyBegin: true}
	e.Host, e.Trust = host, trust
	root := filepath.Join(e.Directory, "authority-transitions")
	operation := filepath.Join(root, e.Request.ID)
	if transitionDirectory(root) != nil || transitionDirectory(operation) != nil {
		t.Fatal("private partial operation")
	}
	partial := map[string][]byte{"intent.json": []byte("{partial intent"), "state.json": []byte("{partial state"), "snapshot.json": []byte("{partial snapshot"), ".orphaned-stage": []byte("retained partial output\n")}
	for name, raw := range partial {
		if writeTransitionFile(filepath.Join(operation, name), raw, true) != nil {
			t.Fatal("partial initialization fixture")
		}
	}
	return e, host, trust, partial
}

func TestPartialPreparationCancellationRetainsOutputAndLostReply(t *testing.T) {
	e, host, trust, partial := partialPreparationFixture(t)
	trust.loseCancel = true
	if _, err := e.CancelPreparation(context.Background()); err == nil || trust.cancellation == nil || CheckNoPendingTransition(e.Directory) == nil {
		t.Fatal("lost cancellation reply cleared unresolved preparation")
	}
	operation := filepath.Join(e.Directory, "authority-transitions", e.Request.ID)
	marker := filepath.Join(operation, preparationCancellationFile)
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("ambiguous cancellation published a terminal marker")
	}
	state, err := e.CancelPreparation(context.Background())
	if err != nil || state.Phase != "aborted" || CheckNoPendingTransition(e.Directory) != nil || host.apply != 0 || host.restore != 0 || trust.begin != 0 {
		t.Fatal("verified partial cancellation failed", err)
	}
	for name, expected := range partial {
		actual, err := os.ReadFile(filepath.Join(operation, name))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("partial output was rewritten or removed")
		}
	}
	checks := host.checks
	host.failOriginal = true // Ordinary maintenance may change live bytes later.
	retry, err := e.CancelPreparation(context.Background())
	if err != nil || !retry.UpdatedAt.Equal(state.UpdatedAt) || !retry.Cancellation.CancelledAt.Equal(state.Cancellation.CancelledAt) || host.checks != checks {
		t.Fatal("completed cancellation replayed verification or changed history", err)
	}
	if _, err := e.Run(context.Background()); err == nil || trust.begin != 0 || host.apply != 0 {
		t.Fatal("cancelled preparation entered staging or admission")
	}
	var record preparationCancellation
	if readTransitionJSON(marker, &record) != nil {
		t.Fatal("read complete cancellation marker")
	}
	record.State.Cancellation.IntentDigest = strings.Repeat("f", 64)
	raw, _ := transitionJSON(record)
	if writeTransitionFile(marker, raw, false) != nil || CheckNoPendingTransition(e.Directory) == nil {
		t.Fatal("uncorrelated cancellation marker cleared maintenance")
	}
}

func TestPartialCancellationRequiresOriginalStateBeforeAndAfterSQL(t *testing.T) {
	for _, second := range []bool{false, true} {
		e, host, trust, _ := partialPreparationFixture(t)
		host.failOriginal, host.failSecond = !second, second
		if _, err := e.CancelPreparation(context.Background()); err == nil || CheckNoPendingTransition(e.Directory) == nil {
			t.Fatal("changed original state reopened maintenance")
		}
		if !second && trust.cancels != 0 || second && trust.cancellation == nil || host.apply != 0 || host.restore != 0 {
			t.Fatal("original-state verification did not fence SQL/live effects")
		}
	}
}

func TestPartialCancellationDoesNotStrandExistingAdmission(t *testing.T) {
	e, original, db := transitionFixture(t)
	trust := &cancellingTrustFixture{transitionTrustFixture: db, loseBegin: true}
	e.Host = &preparationHostFixture{transitionHostFixture: original}
	e.Trust = trust
	if _, err := e.Run(context.Background()); err == nil || db.state == nil || db.state.Phase != "pending" {
		t.Fatal("lost admission fixture")
	}
	if _, err := e.CancelPreparation(context.Background()); err == nil || trust.cancellation != nil {
		t.Fatal("partial cancellation replaced pending admission")
	}
	if state, err := e.Run(context.Background()); err != nil || state.Phase != "committed" {
		t.Fatal("refused cancellation blocked original transition recovery", err)
	}
}

func TestPartialCancellationAfterStateBeforeIntentCompletion(t *testing.T) {
	e, original, db := transitionFixture(t)
	e.Host = &preparationHostFixture{transitionHostFixture: original}
	e.Trust = &cancellingTrustFixture{transitionTrustFixture: db}
	crashTransition(t, e, "state_prepared")
	operation := filepath.Join(e.Directory, "authority-transitions", e.Request.ID)
	if _, err := os.Lstat(filepath.Join(operation, "intent.json")); !os.IsNotExist(err) || db.begin != 0 {
		t.Fatal("initialization fixture already completed or entered admission")
	}
	before, err := os.ReadFile(filepath.Join(operation, "state.json"))
	if err != nil {
		t.Fatal("retained partial initialization state")
	}
	if state, err := e.CancelPreparation(context.Background()); err != nil || state.Phase != "aborted" || CheckNoPendingTransition(e.Directory) != nil {
		t.Fatal("state-before-intent cancellation failed", err)
	}
	after, err := os.ReadFile(filepath.Join(operation, "state.json"))
	if err != nil || !bytes.Equal(before, after) || db.begin != 0 || original.apply != 0 || original.restore != 0 {
		t.Fatal("initialization cancellation repaired partial state or changed live files")
	}
}
