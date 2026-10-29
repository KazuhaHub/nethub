package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

func tokenCommandFixture(t *testing.T) relaytoken.Command {
	t.Helper()
	o := tokenPreparationFixture(t)
	baseline, err := currentRelayTokenBaseline(context.Background(), o.Directory)
	if err != nil {
		t.Fatal("command baseline fixture")
	}
	return relaytoken.Command{Version: 1, Directory: o.Directory, Project: "nethub-stack-test-command",
		SuccessorBackup: o.SuccessorBackup, Request: o.Request, OriginalBaseline: baseline,
		CreatedAt: time.Unix(1700000000, 0).UTC()}
}

func TestNativeRelayTokenCommandRecords(t *testing.T) {
	t.Run("immutable input and read only inspection", func(t *testing.T) {
		command := tokenCommandFixture(t)
		ctx := context.Background()
		if retainRelayTokenCommand(ctx, command) != nil || retainRelayTokenCommand(ctx, command) != nil {
			t.Fatal("original command did not survive an identical retry")
		}
		path := filepath.Join(command.Directory, "token-commands", command.Request.OperationID+".json")
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal("retained command identity")
		}
		got, err := RunRelayTokenCommand(ctx, RelayTokenCommandOptions{Action: "inspect", Directory: command.Directory, OperationID: command.Request.OperationID})
		if err != nil || got.Phase != "preparing" || got.Verified || got.State != nil {
			t.Fatal("inspection claimed runtime verification or changed pending input")
		}
		list, err := RunRelayTokenCommand(ctx, RelayTokenCommandOptions{Action: "inspect", Directory: command.Directory})
		if err != nil || len(list.Operations) != 1 || list.Operations[0].OperationID != command.Request.OperationID {
			t.Fatal("retained command was not discoverable")
		}
		after, err := os.Stat(path)
		if err != nil || !os.SameFile(before, after) {
			t.Fatal("inspection replaced original input")
		}
		if _, err := os.Lstat(filepath.Join(command.Directory, "relay-operation.lock")); !os.IsNotExist(err) {
			t.Fatal("read-only inspection created a mutation lease")
		}
	})
	t.Run("retained input blocks before initialization", func(t *testing.T) {
		command := tokenCommandFixture(t)
		ctx := context.Background()
		if retainRelayTokenCommand(ctx, command) != nil {
			t.Fatal("retained input fixture")
		}
		operation := filepath.Join(command.Directory, "token-transitions", command.Request.OperationID)
		if os.Remove(operation) != nil {
			t.Fatal("pre-initialization fixture")
		}
		if relayauthority.CheckNoPendingTransition(command.Directory) == nil ||
			relayauthority.CheckTokenRecoveryAdmission(command.Directory, command.Request) != nil {
			t.Fatal("retained input did not fence ordinary work before operation creation")
		}
		other := command.Request
		other.OperationID = "12345678-1234-4123-8123-123456789abd"
		if relayauthority.CheckTokenRecoveryAdmission(command.Directory, other) == nil {
			t.Fatal("another incident bypassed the retained command")
		}
	})
	t.Run("competing shared lease refuses execution", func(t *testing.T) {
		command := tokenCommandFixture(t)
		lease, err := hostlease.Acquire(filepath.Join(command.Directory, "relay-operation.lock"))
		if err != nil {
			t.Fatal("held lease fixture")
		}
		defer lease.Close()
		_, err = RunRelayTokenCommand(context.Background(), RelayTokenCommandOptions{Action: "rotate", Directory: command.Directory,
			Project: command.Project, SuccessorBackup: command.SuccessorBackup, OperationID: command.Request.OperationID})
		if err != hostlease.ErrBusy {
			t.Fatal("another protected operation was admitted")
		}
	})
	t.Run("changed retry arguments leave the original record", func(t *testing.T) {
		command := tokenCommandFixture(t)
		ctx := context.Background()
		if retainRelayTokenCommand(ctx, command) != nil {
			t.Fatal("original retry record fixture")
		}
		_, err := RunRelayTokenCommand(ctx, RelayTokenCommandOptions{Action: "rotate", Directory: command.Directory,
			Project: command.Project, SuccessorBackup: command.SuccessorBackup + "-different", OperationID: command.Request.OperationID})
		observed, readErr := readRelayTokenCommand(command.Directory, command.Request.OperationID)
		if err != ErrRelayTokenCommand || readErr != nil || observed != command {
			t.Fatal("changed arguments replaced original input")
		}
	})
	for _, mutation := range []string{"changed baseline", "changed binding", "unknown field", "symlink", "hardlink", "mode", "owner", "different operation", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			command := tokenCommandFixture(t)
			ctx := context.Background()
			if retainRelayTokenCommand(ctx, command) != nil {
				t.Fatal("private command fixture")
			}
			path := filepath.Join(command.Directory, "token-commands", command.Request.OperationID+".json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("original command fixture")
			}
			changed := command
			switch mutation {
			case "changed baseline":
				changed.OriginalBaseline = strings.Repeat("b", 64)
			case "changed binding":
				changed.Request.Binding = strings.Repeat("b", 64)
			case "unknown field":
				var fields map[string]any
				if json.Unmarshal(before, &fields) != nil {
					t.Fatal("metadata fixture")
				}
				fields["private_unexpected"] = "must-not-escape"
				if os.WriteFile(path, authorityJSON(fields), 0600) != nil {
					t.Fatal("unknown metadata fixture")
				}
			case "symlink":
				outside := filepath.Join(filepath.Dir(command.Directory), "outside-command")
				if os.WriteFile(outside, before, 0600) != nil || os.Remove(path) != nil || os.Symlink(outside, path) != nil {
					t.Fatal("symlink fixture")
				}
			case "hardlink":
				if os.Link(path, filepath.Join(filepath.Dir(command.Directory), "linked-command")) != nil {
					t.Fatal("hardlink fixture")
				}
			case "mode":
				if os.Chmod(path, 0644) != nil {
					t.Fatal("mode fixture")
				}
			case "owner":
				if os.Chown(path, 65532, 65532) != nil {
					t.Fatal("owner fixture")
				}
			case "different operation":
				changed.Request.OperationID = "12345678-1234-4123-8123-123456789abd"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if mutation == "unknown field" || mutation == "symlink" || mutation == "hardlink" || mutation == "mode" || mutation == "owner" {
				if _, err := readRelayTokenCommand(command.Directory, command.Request.OperationID); err != ErrRelayTokenCommand {
					t.Fatal("unsafe retained metadata was readable")
				}
			}
			if mutation == "different operation" {
				// A new ID is allowed as retained input, but cannot obtain admission
				// while the first command is unresolved.
				if retainRelayTokenCommand(ctx, changed) != nil || relayauthority.CheckTokenRecoveryAdmission(command.Directory, changed.Request) == nil {
					t.Fatal("another command bypassed unresolved original input")
				}
				return
			}
			if retainRelayTokenCommand(ctx, changed) != ErrRelayTokenCommand {
				t.Fatal("unconfirmed retained input was accepted")
			}
			if mutation == "changed baseline" || mutation == "changed binding" || mutation == "cancelled" {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("refused retry changed original metadata")
				}
			}
		})
	}
}
