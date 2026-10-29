package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
)

func TestNativeRelayTokenRecoveryAdmission(t *testing.T) {
	t.Run("only original pending request can resume", func(t *testing.T) {
		o, _, _ := tokenPublicationFixture(t)
		lease, err := hostlease.Acquire(filepath.Join(o.Directory, "relay-operation.lock"))
		if err != nil {
			t.Fatal("recovery lease fixture")
		}
		defer lease.Close()
		if relayauthority.CheckTokenRecoveryAdmission(o.Directory, o.Request) != nil ||
			relayauthority.CheckNoPendingAuthorityTransition(o.Directory) != nil ||
			relayauthority.CheckNoPendingTransition(o.Directory) == nil {
			t.Fatal("own recovery bypassed ordinary admission or lost its exact request")
		}
	})
	t.Run("empty original initialization remains recoverable", func(t *testing.T) {
		o := tokenPreparationFixture(t)
		if relayauthority.CheckTokenRecoveryAdmission(o.Directory, o.Request) != nil ||
			relayauthority.CheckNoPendingTransition(o.Directory) == nil {
			t.Fatal("empty initialization lost recovery or reopened ordinary admission")
		}
	})
	t.Run("pending authority still blocks token recovery", func(t *testing.T) {
		o, _, _ := tokenPublicationFixture(t)
		root := filepath.Join(o.Directory, "authority-transitions")
		if authorityPrivateDirectory(root) != nil || authorityPrivateDirectory(filepath.Join(root, "12345678-1234-4123-8123-123456789abd")) != nil {
			t.Fatal("pending authority fixture")
		}
		if relayauthority.CheckTokenRecoveryAdmission(o.Directory, o.Request) != nil ||
			relayauthority.CheckNoPendingAuthorityTransition(o.Directory) == nil ||
			relayauthority.CheckNoPendingTransition(o.Directory) == nil {
			t.Fatal("own token admission waived the independent authority barrier")
		}
	})
	for _, mutation := range []string{"changed binding", "another pending token", "missing options in nonempty directory", "wrong directory", "malformed options", "different operation"} {
		t.Run(mutation, func(t *testing.T) {
			o, _, journal := tokenPublicationFixture(t)
			request := o.Request
			switch mutation {
			case "changed binding":
				request.Binding = strings.Repeat("b", 64)
			case "another pending token":
				if authorityPrivateDirectory(filepath.Join(filepath.Dir(journal.directory), "12345678-1234-4123-8123-123456789abd")) != nil {
					t.Fatal("competing request fixture")
				}
			case "missing options in nonempty directory":
				if os.Remove(filepath.Join(journal.directory, "options.json")) != nil {
					t.Fatal("missing options fixture")
				}
			case "wrong directory":
				other := o
				other.Directory = filepath.Dir(o.Directory)
				if os.WriteFile(filepath.Join(journal.directory, "options.json"), authorityJSON(other), 0600) != nil {
					t.Fatal("wrong directory fixture")
				}
			case "malformed options":
				if os.WriteFile(filepath.Join(journal.directory, "options.json"), []byte("{\"private_unexpected\":true}\n"), 0600) != nil {
					t.Fatal("malformed options fixture")
				}
			case "different operation":
				request.OperationID = "12345678-1234-4123-8123-123456789abd"
			}
			if relayauthority.CheckTokenRecoveryAdmission(o.Directory, request) == nil {
				t.Fatal("conflicting original request was admitted")
			}
		})
	}
}
