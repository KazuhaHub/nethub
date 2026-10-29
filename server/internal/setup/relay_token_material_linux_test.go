package setup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

// These fixtures exercise protected filesystem coverage, not valid certificates,
// a live deployment, backup custody or service recovery.
func tokenMaterialFixture(t *testing.T) (relayTokenMaterialOptions, relaytoken.Snapshot) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("protected material verification requires isolated Linux root")
	}
	directory, successor, before, old, next := tokenPlanFixture(t)
	if err := os.Chmod(filepath.Dir(directory), 0700); err != nil {
		t.Fatal("fixture private backup parent", err)
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	o := relayTokenMaterialOptions{Directory: directory, SuccessorBackup: successor, Request: relaytoken.Request{OperationID: "12345678-1234-4123-8123-123456789abc", Binding: strings.Repeat("a", 64)}}
	operation := filepath.Join(directory, "token-transitions", o.Request.OperationID)
	snapshot := filepath.Join(operation, "snapshot")
	for _, name := range []string{filepath.Dir(operation), operation, snapshot, filepath.Join(snapshot, "before"), filepath.Join(snapshot, "after"), filepath.Join(snapshot, "maintenance"), before.BackupDirectory, successor, filepath.Join(successor, "maintenance")} {
		if err := authorityPrivateDirectory(name); err != nil {
			t.Fatal("fixture private directory", filepath.Base(name), err)
		}
	}
	copyFile := func(root, name string, raw []byte) {
		t.Helper()
		if err := authorityCopy(root, filepath.Join(root, filepath.FromSlash(name)), raw); err != nil {
			t.Fatal("private fixture copy", err)
		}
	}
	after, err := relayTokenManifest(directory, successor, before, old, next)
	if err != nil {
		t.Fatal("fixture plan", err)
	}
	payloads := map[string][]byte{}
	owners := expectedOwners()
	for _, file := range before.Files {
		payloads[file.Path] = old
		copyFile(before.BackupDirectory, file.Path, old)
	}
	for _, name := range relayRuntimeFiles {
		payloads[name] = []byte("retained runtime fixture: " + name)
		owners[name] = 65532
	}
	owners["setup.json"] = 0
	original := before
	original.ConfirmedAt = nil
	original.BackupDirectory = ""
	if err := saveManifest(before.BackupDirectory, original); err != nil {
		t.Fatal(err)
	}
	backupManifest, err := authorityRead(filepath.Join(before.BackupDirectory, "setup.json"), 0, 32768)
	if err != nil {
		t.Fatal(err)
	}
	saved := relayTokenMaterial{Version: 1, Options: o, MaintenancePresent: true, OriginalBackupManifest: authorityHash(backupManifest)}
	names := make([]string, 0, len(owners))
	for name := range owners {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		raw := payloads[name]
		changed := raw
		if name == "secrets/authz/frp_token" || name == "secrets/frps/frp_token" {
			changed = next
		}
		if name == "setup.json" {
			raw, err = json.MarshalIndent(before, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, '\n')
			changed, err = json.MarshalIndent(after, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			changed = append(changed, '\n')
		}
		copyFile(filepath.Join(snapshot, "before"), name, raw)
		copyFile(filepath.Join(snapshot, "after"), name, changed)
		copyFile(successor, name, changed)
		saved.Files = append(saved.Files, authoritySnapshotFile{Path: name, Before: authorityHash(raw), After: authorityHash(changed), UID: owners[name]})
	}
	copyFile(operation, "candidate", next)
	copyFile(successor, ".gitignore", []byte("*\n"))
	maintenance := []byte("{\"private_fixture\":true}\n")
	copyFile(filepath.Join(snapshot, "maintenance"), "generation.json", maintenance)
	copyFile(filepath.Join(successor, "maintenance"), "generation.json", maintenance)
	saved.Maintenance, _, err = authorityTree(filepath.Join(snapshot, "maintenance"))
	if err != nil {
		t.Fatal(err)
	}
	raw := authorityJSON(saved)
	copyFile(operation, "snapshot.json", raw)
	return o, relaytoken.Snapshot{Digest: authorityHash(raw), Before: authorityHash(old), After: authorityHash(next)}
}

func TestNativeRelayTokenMaterial(t *testing.T) {
	t.Run("exact retained material and independent complete successor", func(t *testing.T) {
		o, want := tokenMaterialFixture(t)
		got, err := verifyRelayTokenMaterial(context.Background(), o)
		if err != nil || got != want {
			t.Fatal("complete material was not verified", err)
		}
	})
	for _, mutation := range []string{"candidate", "authority", "runtime", "missing current leaf", "extra backup file", "mode", "hardlink", "symlink", "manifest", "unknown metadata", "different request", "different backup", "maintenance", "old backup", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			o, _ := tokenMaterialFixture(t)
			operation := filepath.Join(o.Directory, "token-transitions", o.Request.OperationID)
			target := filepath.Join(o.SuccessorBackup, "runtime/relay/relay-cert.pem")
			outside := filepath.Join(t.TempDir(), "untouched")
			if os.WriteFile(outside, []byte("unrelated value"), 0600) != nil {
				t.Fatal("outside fixture")
			}
			write := func(path string) {
				t.Helper()
				if os.WriteFile(path, []byte("changed"), 0600) != nil {
					t.Fatal("corruption fixture")
				}
			}
			ctx := context.Background()
			switch mutation {
			case "candidate":
				write(filepath.Join(operation, "candidate"))
			case "authority":
				write(filepath.Join(operation, "snapshot/after/secrets/issuer/ca-key.pem"))
			case "runtime":
				write(filepath.Join(operation, "snapshot/after/runtime/relay/relay-key.pem"))
			case "missing current leaf":
				if os.Remove(target) != nil {
					t.Fatal("missing fixture")
				}
			case "extra backup file":
				write(filepath.Join(o.SuccessorBackup, "unexpected"))
			case "mode":
				if os.Chmod(target, 0644) != nil {
					t.Fatal("mode fixture")
				}
			case "hardlink":
				if os.Remove(target) != nil || os.Link(outside, target) != nil {
					t.Fatal("link fixture")
				}
			case "symlink":
				if os.Remove(target) != nil || os.Symlink(outside, target) != nil {
					t.Fatal("link fixture")
				}
			case "manifest":
				write(filepath.Join(operation, "snapshot/after/setup.json"))
			case "unknown metadata":
				file := filepath.Join(operation, "snapshot.json")
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				raw = append(append([]byte(nil), raw[:len(raw)-2]...), []byte(",\"unexpected\":true}\n")...)
				if os.WriteFile(file, raw, 0600) != nil {
					t.Fatal("metadata fixture")
				}
			case "different request":
				o.Request.Binding = strings.Repeat("b", 64)
			case "different backup":
				o.SuccessorBackup = filepath.Join(filepath.Dir(o.SuccessorBackup), "other-backup")
			case "maintenance":
				write(filepath.Join(o.SuccessorBackup, "maintenance/generation.json"))
			case "old backup":
				before, err := Load(filepath.Join(operation, "snapshot/before"))
				if err != nil {
					t.Fatal(err)
				}
				write(filepath.Join(before.BackupDirectory, "secrets/web/secrets_key"))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := verifyRelayTokenMaterial(ctx, o); !errors.Is(err, relaytoken.ErrTransition) {
				t.Fatal("unsafe or incomplete retained material admitted")
			}
			raw, err := os.ReadFile(outside)
			if err != nil || string(raw) != "unrelated value" {
				t.Fatal("verifier changed unrelated material")
			}
		})
	}
}
