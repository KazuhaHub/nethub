package setup

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
)

func TestNativeRelayTokenAdmission(t *testing.T) {
	t.Run("released lease does not clear pending operation", func(t *testing.T) {
		o, _, _ := tokenPublicationFixture(t)
		lease, err := hostlease.Acquire(filepath.Join(o.Directory, "relay-operation.lock"))
		if err != nil {
			t.Fatal("owned lease fixture")
		}
		lease.Close()
		if relayauthority.CheckNoPendingTokenTransition(o.Directory) == nil || relayauthority.CheckNoPendingTransition(o.Directory) == nil {
			t.Fatal("released process lease cleared durable admission")
		}
		if err := CheckAuthority(o.Directory); err == nil || err.Error() != "shared relay token operation requires recovery" {
			t.Fatal("ordinary authority checking ignored pending token operation")
		}
	})
	t.Run("complete bound journal permits admission", func(t *testing.T) {
		o, _, journal := tokenPublicationFixture(t)
		state, err := journal.ReadState(context.Background())
		if err != nil {
			t.Fatal("initial admission state")
		}
		for _, phase := range []string{"published", "reloading", "verifying", "complete"} {
			state.Phase = phase
			if journal.WriteState(context.Background(), state) != nil {
				t.Fatal("synthetic terminal admission state")
			}
		}
		if relayauthority.CheckNoPendingTokenTransition(o.Directory) != nil || relayauthority.CheckNoPendingTransition(o.Directory) != nil {
			t.Fatal("valid complete journal kept admission blocked")
		}
	})
	for _, mutation := range []string{"partial preparation", "unknown options", "wrong directory", "linked state", "public mode", "different operation"} {
		t.Run(mutation, func(t *testing.T) {
			o, _, journal := tokenPublicationFixture(t)
			state, err := journal.ReadState(context.Background())
			if err != nil {
				t.Fatal("initial admission state")
			}
			for _, phase := range []string{"published", "reloading", "verifying", "complete"} {
				state.Phase = phase
				if journal.WriteState(context.Background(), state) != nil {
					t.Fatal("terminal admission fixture")
				}
			}
			operation := journal.directory
			switch mutation {
			case "partial preparation":
				if os.Remove(filepath.Join(operation, "intent.json")) != nil {
					t.Fatal("partial fixture")
				}
			case "unknown options":
				if os.WriteFile(filepath.Join(operation, "options.json"), []byte("{\"unknown\":true}\n"), 0600) != nil {
					t.Fatal("malformed fixture")
				}
			case "wrong directory":
				changed := o
				changed.Directory = filepath.Dir(o.Directory)
				if os.WriteFile(filepath.Join(operation, "options.json"), authorityJSON(changed), 0600) != nil {
					t.Fatal("directory binding fixture")
				}
			case "linked state":
				if os.Link(filepath.Join(operation, "state.json"), filepath.Join(filepath.Dir(o.Directory), "linked-state")) != nil {
					t.Fatal("linked fixture")
				}
			case "public mode":
				if os.Chmod(filepath.Join(operation, "state.json"), 0644) != nil {
					t.Fatal("mode fixture")
				}
			case "different operation":
				if os.Rename(operation, filepath.Join(filepath.Dir(operation), "12345678-1234-4123-8123-123456789abd")) != nil {
					t.Fatal("operation identity fixture")
				}
			}
			if relayauthority.CheckNoPendingTokenTransition(o.Directory) == nil || relayauthority.CheckNoPendingTransition(o.Directory) == nil {
				t.Fatal("unconfirmed terminal admission accepted")
			}
		})
	}
}
