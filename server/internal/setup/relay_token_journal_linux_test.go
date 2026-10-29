package setup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

func tokenJournalFixture(t *testing.T) (relayTokenJournal, relaytoken.Intent) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("protected token journal requires isolated Linux root")
	}
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private token operation directory")
	}
	request := relaytoken.Request{OperationID: "12345678-1234-4123-8123-123456789abc", Binding: strings.Repeat("a", 64)}
	return relayTokenJournal{directory: directory, request: request}, relaytoken.Intent{Version: 1, Request: request,
		Snapshot: relaytoken.Snapshot{Digest: strings.Repeat("b", 64), Before: strings.Repeat("c", 64), After: strings.Repeat("d", 64)}}
}

func tokenState(intent relaytoken.Intent, phase string) relaytoken.State {
	return relaytoken.State{Version: 1, OperationID: intent.Request.OperationID, IntentDigest: intent.Digest(),
		Phase: phase, UpdatedAt: time.Unix(1700000000, 0).UTC()}
}

func TestNativeRelayTokenJournal(t *testing.T) {
	t.Run("ordered durable records and immutable intent", func(t *testing.T) {
		j, intent := tokenJournalFixture(t)
		ctx := context.Background()
		if _, err := j.ReadIntent(ctx); !errors.Is(err, relaytoken.ErrMissing) {
			t.Fatal("new intent must be absent")
		}
		if j.WriteIntent(ctx, intent) != nil || j.WriteIntent(ctx, intent) != nil {
			t.Fatal("intent was not retained idempotently")
		}
		changed := intent
		changed.Snapshot.After = strings.Repeat("e", 64)
		if j.WriteIntent(ctx, changed) == nil {
			t.Fatal("original candidate was overwritten")
		}
		if j.WriteState(ctx, tokenState(intent, "published")) == nil {
			t.Fatal("initial phase skipped publication intent")
		}
		for _, phase := range []string{"prepared", "publishing", "published", "reloading", "verifying", "complete"} {
			state := tokenState(intent, phase)
			if j.WriteState(ctx, state) != nil {
				t.Fatal("valid phase was not persisted")
			}
			if actual, err := j.ReadState(ctx); err != nil || actual != state {
				t.Fatal("phase readback differs")
			}
		}
		if j.WriteState(ctx, tokenState(intent, "prepared")) == nil {
			t.Fatal("completed operation moved backwards")
		}
		info, err := os.Lstat(filepath.Join(j.directory, "state.json"))
		if err != nil || info.Mode().Perm() != 0600 || ownerUID(filepath.Join(j.directory, "state.json")) != 0 {
			t.Fatal("journal lost private ownership/mode")
		}
	})
	t.Run("concurrent different candidates have one winner", func(t *testing.T) {
		j, intent := tokenJournalFixture(t)
		other := intent
		other.Snapshot.After = strings.Repeat("e", 64)
		var group sync.WaitGroup
		results := make(chan error, 2)
		for _, candidate := range []relaytoken.Intent{intent, other} {
			group.Add(1)
			go func() { defer group.Done(); results <- j.WriteIntent(context.Background(), candidate) }()
		}
		group.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			}
		}
		if success != 1 {
			t.Fatal("immutable publication did not select exactly one original candidate")
		}
	})
	for _, mutation := range []string{"symlink", "hardlink", "unknown field", "mode", "owner", "orphan", "removed directory"} {
		t.Run(mutation, func(t *testing.T) {
			j, intent := tokenJournalFixture(t)
			ctx := context.Background()
			original := authorityJSON(intent)
			target := filepath.Join(j.directory, "intent.json")
			outside := filepath.Join(t.TempDir(), "unrelated.json")
			if os.WriteFile(outside, original, 0600) != nil {
				t.Fatal("outside fixture")
			}
			switch mutation {
			case "symlink":
				if os.Symlink(outside, target) != nil {
					t.Fatal("link fixture")
				}
			case "hardlink":
				if os.Link(outside, target) != nil {
					t.Fatal("link fixture")
				}
			case "unknown field":
				bad := append(append([]byte(nil), original[:len(original)-2]...), []byte(",\"unexpected\":true}\n")...)
				if os.WriteFile(target, bad, 0600) != nil {
					t.Fatal("closed record fixture")
				}
			case "mode":
				if os.WriteFile(target, original, 0644) != nil {
					t.Fatal("mode fixture")
				}
				if os.Chmod(target, 0644) != nil {
					t.Fatal("unsafe fixture mode")
				}
			case "owner":
				if os.WriteFile(target, original, 0600) != nil || os.Chown(target, 65532, 65532) != nil {
					t.Fatal("unsafe fixture owner")
				}
			case "orphan":
				if os.WriteFile(filepath.Join(j.directory, "state.json"), authorityJSON(tokenState(intent, "prepared")), 0600) != nil {
					t.Fatal("orphan fixture")
				}
			case "removed directory":
				if os.Remove(j.directory) != nil {
					t.Fatal("empty owned directory fixture")
				}
			}
			if j.WriteIntent(ctx, intent) == nil {
				t.Fatal("unsafe or ambiguous original intent was replaced")
			}
			raw, err := os.ReadFile(outside)
			if err != nil || !bytes.Equal(raw, original) {
				t.Fatal("outside material changed")
			}
		})
	}
}
