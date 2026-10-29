package setup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

// Build only synthetic protected files. This does not exercise real certificate
// validation, host admission, live publication, service reload or device recovery.
func tokenPreparationFixture(t *testing.T) relayTokenMaterialOptions {
	t.Helper()
	o, _ := tokenMaterialFixture(t)
	operation := filepath.Join(o.Directory, "token-transitions", o.Request.OperationID)
	root := filepath.Join(operation, "snapshot/before")
	owners := expectedOwners()
	for _, name := range relayRuntimeFiles {
		owners[name] = 65532
	}
	owners["setup.json"] = 0
	for name := range owners {
		data, err := authorityRead(filepath.Join(root, filepath.FromSlash(name)), 0, 32768)
		target := filepath.Join(o.Directory, filepath.FromSlash(name))
		if err != nil || authorityCopy(o.Directory, target, data) != nil {
			t.Fatal("synthetic live input", name)
		}
	}
	for name, uid := range owners {
		target := filepath.Join(o.Directory, filepath.FromSlash(name))
		if os.Chown(target, uid, 0) != nil || os.Chown(filepath.Dir(target), uid, 0) != nil {
			t.Fatal("synthetic live ownership", name)
		}
	}
	// Only these two fixture-owned children are removed; all live source material
	// and the independent original backup remain for preparation/readback tests.
	for _, target := range []string{operation, o.SuccessorBackup} {
		if !tokenPathsContained(filepath.Dir(o.Directory), target) || os.RemoveAll(target) != nil {
			t.Fatal("synthetic fixture reset")
		}
	}
	if authorityPrivateDirectory(operation) != nil {
		t.Fatal("private operation fixture")
	}
	return o
}

func TestNativeRelayTokenPreparation(t *testing.T) {
	t.Run("complete independent copy and immutable retry", func(t *testing.T) {
		o := tokenPreparationFixture(t)
		old, err := authorityRead(filepath.Join(o.Directory, "secrets/authz/frp_token"), 65532, 65)
		if err != nil {
			t.Fatal("fixture original token")
		}
		first, err := prepareRelayTokenMaterial(context.Background(), o)
		second, again := prepareRelayTokenMaterial(context.Background(), o)
		observed, verified := verifyRelayTokenMaterial(context.Background(), o)
		current, currentErr := authorityRead(filepath.Join(o.Directory, "secrets/authz/frp_token"), 65532, 65)
		if err != nil || again != nil || verified != nil || currentErr != nil || first != second || first != observed ||
			!bytes.Equal(old, current) || first.Before == first.After || first.Digest == "" {
			t.Fatal("preparation did not retain complete independent material", err, again, verified)
		}
	})
	for _, mutation := range []string{"partial copies", "changed baseline", "changed binding", "cancelled", "conflicting backup", "linked candidate"} {
		t.Run(mutation, func(t *testing.T) {
			o := tokenPreparationFixture(t)
			first, err := prepareRelayTokenMaterial(context.Background(), o)
			if err != nil {
				t.Fatal("initial fixture preparation", err)
			}
			operation := filepath.Join(o.Directory, "token-transitions", o.Request.OperationID)
			candidate := filepath.Join(operation, "candidate")
			retained, err := authorityRead(candidate, 0, 65)
			if err != nil || os.Remove(filepath.Join(operation, "snapshot.json")) != nil {
				t.Fatal("partial preparation fixture")
			}
			ctx := context.Background()
			switch mutation {
			case "partial copies":
				if os.Remove(filepath.Join(operation, "snapshot/after/runtime/relay/relay-key.pem")) != nil {
					t.Fatal("partial copy fixture")
				}
			case "changed baseline":
				if os.WriteFile(filepath.Join(o.Directory, "runtime/relay/relay-key.pem"), []byte("changed baseline"), 0600) != nil {
					t.Fatal("baseline mutation")
				}
			case "changed binding":
				o.Request.Binding = strings.Repeat("b", 64)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "conflicting backup":
				if os.WriteFile(filepath.Join(o.SuccessorBackup, "runtime/relay/relay-key.pem"), []byte("unrelated backup"), 0600) != nil {
					t.Fatal("backup mutation")
				}
			case "linked candidate":
				outside := filepath.Join(filepath.Dir(o.Directory), "outside")
				if os.WriteFile(outside, retained, 0600) != nil || os.Remove(candidate) != nil || os.Symlink(outside, candidate) != nil {
					t.Fatal("candidate link fixture")
				}
			}
			got, err := prepareRelayTokenMaterial(ctx, o)
			if mutation == "partial copies" {
				if err != nil || got != first {
					t.Fatal("partial preparation did not reuse candidate and baseline", err)
				}
			} else if err != relaytoken.ErrTransition {
				t.Fatal("conflicting preparation accepted", err)
			}
			if mutation != "linked candidate" {
				after, err := authorityRead(candidate, 0, 65)
				if err != nil || !bytes.Equal(after, retained) {
					t.Fatal("retained candidate changed")
				}
			}
		})
	}
}
