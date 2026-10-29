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
	"testing"
	"time"
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
	run := func(action string, arguments ...string) RelayTokenCommandResult {
		t.Helper()
		command := exec.CommandContext(ctx, binary, append([]string{"relay-token", action, "--directory", directory}, arguments...)...)
		command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
		command.Stderr = io.Discard
		command.WaitDelay = 2 * time.Second
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
	beforeIDs := ids()
	previous, err := authorityRead(filepath.Join(directory, "secrets/authz/frp_token"), 65532, 65)
	backupManifest, backupErr := authorityRead(filepath.Join(manifest.BackupDirectory, "setup.json"), 0, 32768)
	id, idErr := newRelayTokenOperationID()
	if err != nil || backupErr != nil || idErr != nil {
		t.Fatal("original private runtime inputs unavailable")
	}
	successor := filepath.Join(stage, "token-successor-"+id)
	first := run("rotate", "--project-name", project, "--compose-file", compose, "--successor-backup", successor, "--operation-id", id)
	if !first.Verified || !first.DeviceRotationRequired || first.OperationID != id || first.Phase != "complete" || first.State == nil || first.State.Phase != "complete" {
		t.Fatal("actual token operation did not confirm completion and device rotation requirement")
	}
	afterIDs := ids()
	for name, before := range beforeIDs {
		changed := name == "nethub-authz" || name == "frps"
		if (afterIDs[name] != before) != changed {
			t.Fatal("token cutover recreated an unrelated service or failed to recreate its bound target")
		}
	}
	candidate, err := authorityRead(filepath.Join(directory, "secrets/authz/frp_token"), 65532, 65)
	if err != nil || bytes.Equal(candidate, previous) || CheckFiles(directory) != nil {
		t.Fatal("published candidate or complete independent backup unconfirmed")
	}
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
	outcome := map[string]any{"passed": true, "actual_compiled_server_token_command": true,
		"actual_bound_two_service_reload": true, "other_four_services_unchanged": true,
		"actual_candidate_previous_candidate_Login_verified": true, "served_relay_leaf_verified": true,
		"complete_current_key_successor_verified": true, "original_backup_retained": true,
		"complete_retry_same_candidate_without_reload": true, "online_or_native_fleet_recovery_accepted": false}
	if os.WriteFile(resultPath, authorityJSON(outcome), 0600) != nil {
		t.Fatal("closed actual runtime outcome could not be retained")
	}
	t.Log("Actual compiled token rotation completed two-service reload and candidate/previous/candidate Login; four unrelated services and the original backup survived, and complete retry retained its candidate without reload")
}
