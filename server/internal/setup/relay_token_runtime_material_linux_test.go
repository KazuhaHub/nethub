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

// These synthetic protected files test phase/material admission only. No valid
// certificate, database, Docker service or successful runtime probe is modeled.
func tokenRuntimeMaterialFixture(t *testing.T, phase string) (*relayTokenRuntimeHost, relaytoken.Intent, relayTokenJournal, *int) {
	t.Helper()
	o := tokenPreparationFixture(t)
	manifest, err := Load(o.Directory)
	if err != nil {
		t.Fatal("runtime material manifest fixture")
	}
	originalBaseline, err := currentRelayTokenBaseline(context.Background(), o.Directory)
	if err != nil {
		t.Fatal("original live material digest fixture")
	}
	calls := new(int)
	service := &BoundRelayAuthorityService{binding: authorityServiceBinding{
		Version: 1, Directory: o.Directory, Project: "nethub-stack-test-token-runtime", Config: manifest.Config,
		Files: map[string]string{}, Images: map[string]authorityServiceImage{},
	}}
	service.command = func(context.Context, ...string) ([]byte, error) {
		*calls += 1
		return nil, ErrRelayAuthority
	}
	o.Request.Binding = service.Fingerprint()
	snapshot, err := prepareRelayTokenMaterial(context.Background(), o)
	if err != nil {
		t.Fatal("runtime material preparation", err)
	}
	intent := relaytoken.Intent{Version: 1, Request: o.Request, Snapshot: snapshot}
	journal := relayTokenJournal{directory: filepath.Join(o.Directory, "token-transitions", o.Request.OperationID), request: o.Request}
	state := relaytoken.State{Version: 1, OperationID: o.Request.OperationID, IntentDigest: intent.Digest(), Phase: "prepared", UpdatedAt: time.Now().UTC()}
	if journal.WriteIntent(context.Background(), intent) != nil || journal.WriteState(context.Background(), state) != nil {
		t.Fatal("runtime material initial journal")
	}
	state.Phase = "publishing"
	if journal.WriteState(context.Background(), state) != nil || publishRelayTokenMaterial(context.Background(), o, intent) != nil {
		t.Fatal("runtime material publication")
	}
	for _, next := range []string{"published", "reloading", "verifying", "complete"} {
		state.Phase = next
		if journal.WriteState(context.Background(), state) != nil {
			t.Fatal("runtime material phase fixture")
		}
		if next == phase {
			baseline, err := snapshotRelayTokenBaseline(context.Background(), o)
			if err != nil || baseline != originalBaseline {
				t.Fatal("original material digest fixture")
			}
			return &relayTokenRuntimeHost{options: o, service: service, baseline: originalBaseline}, intent, journal, calls
		}
	}
	t.Fatal("unknown fixture phase")
	return nil, relaytoken.Intent{}, relayTokenJournal{}, nil
}

func TestNativeRelayTokenRuntimeMaterial(t *testing.T) {
	t.Run("exact candidate gate", func(t *testing.T) {
		host, intent, _, calls := tokenRuntimeMaterialFixture(t, "reloading")
		if host.published(context.Background(), intent, "reloading") != nil || *calls != 0 {
			t.Fatal("exact candidate admission touched a service or refused material")
		}
	})
	t.Run("complete permits verification but never reload", func(t *testing.T) {
		host, intent, _, calls := tokenRuntimeMaterialFixture(t, "complete")
		if host.published(context.Background(), intent, "verifying", "complete") != nil ||
			host.Reload(context.Background(), intent) != relaytoken.ErrTransition || *calls != 0 {
			t.Fatal("completed retry was allowed to reload or lost verification admission")
		}
	})
	for _, mutation := range []string{"wrong phase", "changed binding", "changed original baseline", "unknown live material", "damaged backup", "changed maintenance", "wrong snapshot", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			phase := "reloading"
			if mutation == "wrong phase" {
				phase = "published"
			}
			host, intent, _, calls := tokenRuntimeMaterialFixture(t, phase)
			path := filepath.Join(host.options.Directory, "secrets/authz/frp_token")
			before, err := authorityRead(path, 65532, 65)
			if err != nil {
				t.Fatal("runtime refusal token fixture")
			}
			ctx := context.Background()
			switch mutation {
			case "changed binding":
				host.service.binding.Project = "nethub-stack-test-different"
			case "changed original baseline":
				host.baseline = strings.Repeat("b", 64)
			case "unknown live material":
				if os.WriteFile(filepath.Join(host.options.Directory, "runtime/relay/relay-key.pem"), []byte("unknown"), 0600) != nil {
					t.Fatal("unknown material fixture")
				}
			case "damaged backup":
				if os.WriteFile(filepath.Join(host.options.SuccessorBackup, "runtime/trust/relay-ca.pem"), []byte("damaged"), 0600) != nil {
					t.Fatal("backup fixture")
				}
			case "changed maintenance":
				directory := filepath.Join(host.options.Directory, "secrets/issuer/maintenance")
				if authorityPrivateDirectory(directory) != nil || authorityCopy(directory, filepath.Join(directory, "unexpected"), []byte("changed")) != nil {
					t.Fatal("maintenance fixture")
				}
			case "wrong snapshot":
				intent.Snapshot.Digest = strings.Repeat("b", 64)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if host.Reload(ctx, intent) != relaytoken.ErrTransition || *calls != 0 {
				t.Fatal("unconfirmed reload reached a service")
			}
			after, err := authorityRead(path, 65532, 65)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refused reload changed a token")
			}
		})
	}
}
