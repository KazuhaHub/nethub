package setup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

func tokenPublicationFixture(t *testing.T) (relayTokenMaterialOptions, relaytoken.Intent, relayTokenJournal) {
	t.Helper()
	o := tokenPreparationFixture(t)
	snapshot, err := prepareRelayTokenMaterial(context.Background(), o)
	if err != nil {
		t.Fatal("publication preparation", err)
	}
	intent := relaytoken.Intent{Version: 1, Request: o.Request, Snapshot: snapshot}
	j := relayTokenJournal{directory: filepath.Join(o.Directory, "token-transitions", o.Request.OperationID), request: o.Request}
	state := relaytoken.State{Version: 1, OperationID: o.Request.OperationID, IntentDigest: intent.Digest(), Phase: "prepared", UpdatedAt: time.Now().UTC()}
	if j.WriteIntent(context.Background(), intent) != nil || j.WriteState(context.Background(), state) != nil {
		t.Fatal("durable publication fixture")
	}
	state.Phase = "publishing"
	if j.WriteState(context.Background(), state) != nil {
		t.Fatal("durable publication admission")
	}
	return o, intent, j
}

func TestNativeRelayTokenPublication(t *testing.T) {
	for _, interruption := range []string{"none", "secrets/authz/frp_token", "secrets/frps/frp_token", "setup.json"} {
		name := strings.ReplaceAll(interruption, "/", "_")
		t.Run(name, func(t *testing.T) {
			o, intent, journal := tokenPublicationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := publishRelayTokenMaterialWithCheckpoint(ctx, o, intent, func(path string) {
				if path == interruption {
					cancel()
				}
			})
			if interruption == "none" && err != nil || interruption != "none" && err != relaytoken.ErrTransition {
				t.Fatal("publication interruption outcome", err)
			}
			if err := publishRelayTokenMaterial(context.Background(), o, intent); err != nil {
				t.Fatal("same-candidate publication recovery", err)
			}
			identities := map[string]os.FileInfo{}
			for _, path := range []string{"secrets/authz/frp_token", "secrets/frps/frp_token", "setup.json"} {
				info, err := os.Stat(filepath.Join(o.Directory, filepath.FromSlash(path)))
				if err != nil {
					t.Fatal("published file identity")
				}
				identities[path] = info
			}
			if publishRelayTokenMaterial(context.Background(), o, intent) != nil {
				t.Fatal("idempotent publication retry")
			}
			for path, original := range identities {
				info, err := os.Stat(filepath.Join(o.Directory, filepath.FromSlash(path)))
				if err != nil || !os.SameFile(original, info) {
					t.Fatal("already-published inode was replaced")
				}
			}
			manifest, err := Load(o.Directory)
			if err != nil || manifest.BackupDirectory != o.SuccessorBackup || verifyFiles(o.Directory, manifest.Files) != nil {
				t.Fatal("live candidate manifest did not verify")
			}
			state, err := journal.ReadState(context.Background())
			if err != nil || state.Phase != "publishing" {
				t.Fatal("file publisher claimed reload or incident completion")
			}
		})
	}
	for _, mutation := range []string{"unknown live state", "changed maintenance", "damaged backup", "wrong binding", "wrong snapshot", "complete journal", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			o, intent, journal := tokenPublicationFixture(t)
			original, err := authorityRead(filepath.Join(o.Directory, "secrets/authz/frp_token"), 65532, 65)
			if err != nil {
				t.Fatal("original publication token")
			}
			ctx := context.Background()
			switch mutation {
			case "unknown live state":
				if os.WriteFile(filepath.Join(o.Directory, "runtime/relay/relay-key.pem"), []byte("unrecognized"), 0600) != nil {
					t.Fatal("unrecognized runtime fixture")
				}
			case "changed maintenance":
				dir := filepath.Join(o.Directory, "secrets/issuer/maintenance")
				if authorityPrivateDirectory(dir) != nil || authorityCopy(dir, filepath.Join(dir, "unexpected"), []byte("changed")) != nil {
					t.Fatal("maintenance mutation fixture")
				}
			case "damaged backup":
				if os.WriteFile(filepath.Join(o.SuccessorBackup, "runtime/relay/relay-key.pem"), []byte("damaged"), 0600) != nil {
					t.Fatal("damaged backup fixture")
				}
			case "wrong binding":
				intent.Request.Binding = strings.Repeat("b", 64)
			case "wrong snapshot":
				intent.Snapshot.Digest = strings.Repeat("b", 64)
			case "complete journal":
				state, err := journal.ReadState(ctx)
				if err != nil {
					t.Fatal("complete journal fixture")
				}
				for _, phase := range []string{"published", "reloading", "verifying", "complete"} {
					state.Phase = phase
					if journal.WriteState(ctx, state) != nil {
						t.Fatal("complete journal phase")
					}
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if publishRelayTokenMaterial(ctx, o, intent) != relaytoken.ErrTransition {
				t.Fatal("unconfirmed publication admitted")
			}
			after, err := authorityRead(filepath.Join(o.Directory, "secrets/authz/frp_token"), 65532, 65)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("refused publication changed active token")
			}
		})
	}
}
