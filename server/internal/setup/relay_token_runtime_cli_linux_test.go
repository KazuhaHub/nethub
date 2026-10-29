package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

// Optional in ordinary unit runs, mandatory with a genuine isolated deployment
// in the Compose harness. The caller refreshes the real online clients afterward.
func TestNativeRelayTokenRuntimeCLI(t *testing.T) {
	directory := os.Getenv("NETHUB_TEST_TOKEN_DEPLOYMENT")
	if directory == "" {
		t.Skip("actual owned Compose deployment required")
	}
	project, compose, binary := os.Getenv("NETHUB_TEST_TOKEN_PROJECT"), os.Getenv("NETHUB_TEST_TOKEN_COMPOSE"), os.Getenv("NETHUB_TEST_TOKEN_CLI")
	label := os.Getenv("NETHUB_TEST_TOKEN_RUNTIME_LABEL")
	if label == "" {
		label = "reference"
	}
	stage := filepath.Dir(directory)
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" ||
		!tokenCommandDirectory(stage) || filepath.Base(directory) != "deployment" ||
		filepath.Dir(stage) != "/tmp" && filepath.Dir(stage) != "/var/tmp" ||
		!strings.HasPrefix(project, "nethub-stack-test-") || !projectName.MatchString(project) ||
		compose != filepath.Join(stage, "test.yml") || binary != filepath.Join(stage, "http01-nethub") ||
		!slices.Contains([]string{"reference", "native"}, label) {
		t.Fatal("fresh hosted root and owned runtime fixture required")
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0700 || !guiRootFile(info) {
		t.Fatal("actual protected CLI binary unavailable")
	}
	manifest, err := Load(directory)
	if err != nil || manifest.Config.ConsoleHost != "console.example.com" || manifest.Config.DeviceDomain != "router.example.com" || CheckFiles(directory) != nil {
		t.Fatal("owned confirmed test deployment unavailable")
	}
	resultPath := filepath.Join(stage, "relay-test", "shared-token-runtime-"+label+".json")
	if _, err := os.Lstat(resultPath); !os.IsNotExist(err) {
		t.Fatal("runtime fixture result must be new")
	}
	phase := "runtime_binding"
	t.Cleanup(func() {
		if t.Failed() {
			_ = os.WriteFile(resultPath, authorityJSON(map[string]any{"passed": false, "phase": phase}), 0600)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	service, err := BindRelayAuthorityService(ctx, directory, project, compose, "")
	if err != nil {
		t.Fatal("actual runtime service binding unavailable")
	}
	ids := func() map[string]string {
		t.Helper()
		result := map[string]string{}
		for _, name := range []string{"postgres", "nethub-web", "nethub-authz", "frps", "caddy", "backup"} {
			raw, err := service.host.docker(ctx, append(append([]string{}, service.host.compose...), "ps", "--quiet", name)...)
			if err != nil || !guiContainerID.Match(raw) {
				t.Fatal("owned running service inventory unavailable")
			}
			result[name] = string(raw)
		}
		return result
	}
	cli := func(action string, arguments ...string) *exec.Cmd {
		command := exec.CommandContext(ctx, binary, append([]string{"relay-token", action, "--directory", directory}, arguments...)...)
		command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
		command.Stderr = io.Discard
		command.WaitDelay = 2 * time.Second
		return command
	}
	run := func(action string, arguments ...string) RelayTokenCommandResult {
		t.Helper()
		command := cli(action, arguments...)
		output := guiOutput{limit: 65536}
		command.Stdout = &output
		err := command.Run()
		var result RelayTokenCommandResult
		decoded := json.Unmarshal(output.Bytes(), &result)
		if err != nil || decoded != nil || output.overflow {
			phase := "unclassified"
			if slices.Contains([]string{"preparing", "prepared", "publishing", "published", "reloading", "verifying", "complete", "local_review"}, result.Phase) {
				phase = result.Phase
			}
			t.Fatal("actual relay-token CLI failed at closed phase " + phase)
		}
		return result
	}
	prior := run("inspect")
	if label == "native" && len(prior.Operations) != 1 {
		t.Fatal("native incident requires the completed reference operation")
	}
	beforeIDs := ids()
	phase = "original_input"
	previous, err := authorityRead(filepath.Join(directory, "secrets/authz/frp_token"), 65532, 65)
	backupManifest, backupErr := authorityRead(filepath.Join(manifest.BackupDirectory, "setup.json"), 0, 32768)
	id, idErr := newRelayTokenOperationID()
	if err != nil || backupErr != nil || idErr != nil {
		t.Fatal("original private runtime inputs unavailable")
	}
	successor := filepath.Join(stage, "token-successor-"+id)
	phase = "durable_reload_interrupt"
	// Interrupt the actual process after its durable reload decision. No product
	// fault hook or replacement Docker executable participates in this fixture.
	command := cli("rotate", "--project-name", project, "--compose-file", compose, "--successor-backup", successor, "--operation-id", id)
	interruptedOutput := guiOutput{limit: 65536}
	command.Stdout = &interruptedOutput
	if command.Start() != nil {
		t.Fatal("actual interruptible token command could not start")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	finished := false
	defer func() {
		if !finished {
			_ = command.Process.Kill()
			<-done
		}
	}()
	journal := relayTokenJournal{directory: filepath.Join(directory, "token-transitions", id),
		request: relaytoken.Request{OperationID: id, Binding: service.Fingerprint()}}
	deadline := time.Now().Add(45 * time.Second)
	for {
		select {
		case <-done:
			finished = true
			t.Fatal("actual token command ended before its required reload interruption")
		default:
		}
		state, err := journal.ReadState(ctx)
		if err == nil && state.Phase == "reloading" {
			if command.Process.Signal(syscall.SIGTERM) != nil {
				t.Fatal("actual token command interruption unavailable")
			}
			select {
			case err := <-done:
				finished = true
				if err == nil {
					t.Fatal("interrupted command incorrectly reported success")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("interrupted token command did not terminate")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("durable token reload phase was not observed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	retainedState, err := journal.ReadState(ctx)
	interruptedToken, tokenErr := authorityRead(filepath.Join(directory, "secrets/authz/frp_token"), 65532, 65)
	if err != nil || retainedState.Phase != "reloading" || tokenErr != nil || bytes.Equal(interruptedToken, previous) ||
		relayauthority.CheckNoPendingTransition(directory) == nil || interruptedOutput.overflow {
		t.Fatal("interrupted command lost its candidate, reload decision or ordinary-work fence")
	}
	phase = "resume"
	first := run("resume", "--operation-id", id)
	if !first.Verified || !first.DeviceRotationRequired || first.OperationID != id || first.Phase != "complete" || first.State == nil || first.State.Phase != "complete" {
		t.Fatal("actual token operation did not confirm completion and device rotation requirement")
	}
	afterIDs := ids()
	phase = "published_runtime"
	for name, before := range beforeIDs {
		changed := name == "nethub-authz" || name == "frps"
		if (afterIDs[name] != before) != changed {
			t.Fatal("token cutover recreated an unrelated service or failed to recreate its bound target")
		}
	}
	candidate, err := authorityRead(filepath.Join(directory, "secrets/authz/frp_token"), 65532, 65)
	if err != nil || bytes.Equal(candidate, previous) || !bytes.Equal(candidate, interruptedToken) || CheckFiles(directory) != nil {
		t.Fatal("published candidate or complete independent backup unconfirmed")
	}
	phase = "complete_retry"
	inspected := run("inspect", "--operation-id", id)
	if inspected.Verified || inspected.State == nil || inspected.State.Phase != "complete" {
		t.Fatal("inspection either lost the durable state or claimed fresh runtime verification")
	}
	retry := run("resume", "--operation-id", id)
	if !retry.Verified || retry.State == nil || *retry.State != *first.State {
		t.Fatal("completed retry changed its durable decision")
	}
	for name, current := range ids() {
		if current != afterIDs[name] {
			t.Fatal("completed retry recreated a service")
		}
	}
	retained, err := authorityRead(filepath.Join(directory, "secrets/authz/frp_token"), 65532, 65)
	oldBackup, oldErr := authorityRead(filepath.Join(manifest.BackupDirectory, "setup.json"), 0, 32768)
	if err != nil || oldErr != nil || !bytes.Equal(retained, candidate) || !bytes.Equal(oldBackup, backupManifest) {
		t.Fatal("retry replaced its candidate or original backup")
	}
	phase = "superseded_refusal"
	for _, priorOperation := range prior.Operations {
		if priorOperation.Phase != "complete" {
			t.Fatal("earlier retained operation was not complete")
		}
		old := cli("resume", "--operation-id", priorOperation.OperationID)
		output := guiOutput{limit: 65536}
		old.Stdout = &output
		err := old.Run()
		var refused RelayTokenCommandResult
		if err == nil || output.overflow || json.Unmarshal(output.Bytes(), &refused) != nil || refused.Verified {
			t.Fatal("a superseded completed operation was not refused")
		}
		for name, current := range ids() {
			if current != afterIDs[name] {
				t.Fatal("superseded operation re-created a service")
			}
		}
		current, err := authorityRead(filepath.Join(directory, "secrets/authz/frp_token"), 65532, 65)
		if err != nil || !bytes.Equal(current, candidate) {
			t.Fatal("superseded operation rolled back the candidate")
		}
	}
	outcome := map[string]any{"passed": true, "actual_compiled_server_token_command": true,
		"actual_SIGTERM_during_durable_reload_resumed_same_candidate": true,
		"superseded_complete_operation_refused_without_rollback":      len(prior.Operations) > 0,
		"actual_bound_two_service_reload":                             true, "other_four_services_unchanged": true,
		"actual_candidate_previous_candidate_Login_verified": true, "served_relay_leaf_verified": true,
		"complete_current_key_successor_verified": true, "original_backup_retained": true,
		"complete_retry_same_candidate_without_reload": true, "online_or_native_fleet_recovery_accepted": false}
	if os.WriteFile(resultPath, authorityJSON(outcome), 0600) != nil {
		t.Fatal("closed actual runtime outcome could not be retained")
	}
	t.Log("Actual compiled token rotation resumed SIGTERM during durable reload with the same candidate, completed two-service reload and candidate/previous/candidate Login; four unrelated services and the original backup survived, and complete retry did not reload")
}
