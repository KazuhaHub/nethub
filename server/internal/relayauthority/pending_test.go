package relayauthority

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPendingTransitionBlocksOrdinaryMaintenanceAfterLeaseRelease(t *testing.T) {
	e, _, _ := transitionFixture(t)
	if CheckNoPendingTransition(e.Directory) != nil {
		t.Fatal("fresh deployment blocked")
	}
	crashTransition(t, e, "host_applied")
	if CheckNoPendingTransition(e.Directory) == nil {
		t.Fatal("released lease reopened maintenance")
	}
	state, _ := e.Run(context.Background())
	if state.Phase != "rolled_back" || CheckNoPendingTransition(e.Directory) != nil {
		t.Fatal("verified rollback did not reopen maintenance")
	}
	if os.Remove(filepath.Join(e.Directory, "authority-transitions", e.Request.ID, "state.json")) != nil {
		t.Fatal("remove fixture state")
	}
	if CheckNoPendingTransition(e.Directory) == nil {
		t.Fatal("missing state reopened maintenance")
	}
}

func TestPartialTransitionDirectoryNeverMeansCompletion(t *testing.T) {
	e, _, _ := transitionFixture(t)
	root := filepath.Join(e.Directory, "authority-transitions")
	if os.Mkdir(root, 0700) != nil || os.Mkdir(filepath.Join(root, "partial"), 0700) != nil {
		t.Fatal("partial fixture")
	}
	if CheckNoPendingTransition(e.Directory) == nil {
		t.Fatal("partial initialization reopened maintenance")
	}
}
