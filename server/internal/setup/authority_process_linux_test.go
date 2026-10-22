package setup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"github.com/KazuhaHub/nethub/server/internal/relaycert"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

type authorityCrashInput struct {
	Options RelayAuthoritySnapshotOptions `json:"options"`
	Project string                        `json:"project"`
	Compose string                        `json:"compose"`
	Point   string                        `json:"point"`
}

func crashPublisher(ctx context.Context, service *BoundRelayAuthorityService) (*relaytrust.Publisher, guiissuer.SQLRunner, error) {
	binding, err := service.host.database(ctx)
	if err != nil {
		return nil, nil, err
	}
	run, err := guiissuer.NewDockerSQLRunner(binding)
	if err != nil {
		return nil, nil, err
	}
	return &relaytrust.Publisher{Run: relaytrust.SQLRunner(run), ServerName: service.binding.Config.ConsoleHost}, run, nil
}

// The fault hook exists only in this acceptance test binary. The child exits
// its own process after durable checkpoints; no production flag can enable it.
func TestAuthorityCrashHelper(t *testing.T) {
	inputPath := os.Getenv("NETHUB_AUTHORITY_CRASH_INPUT")
	if inputPath == "" {
		t.Skip("private owned-child authority recovery helper")
	}
	if os.Geteuid() != 0 {
		t.Fatal("helper requires protected disposable root fixture")
	}
	raw, err := authorityRead(inputPath, 0, 16384)
	var input authorityCrashInput
	if err != nil || json.Unmarshal(raw, &input) != nil || !bytes.Equal(raw, authorityJSON(input)) || !input.Options.Request.Valid() {
		t.Fatal("private helper input unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	service, err := BindRelayAuthorityService(ctx, input.Options.Directory, input.Project, input.Compose, "")
	if err != nil || service.Fingerprint() != input.Options.ServiceFingerprint {
		t.Fatal("helper service binding")
	}
	ca, err := authorityRead(filepath.Join(input.Options.Directory, "secrets/issuer/ca.pem"), 0, 32768)
	if err != nil {
		t.Fatal("helper predecessor")
	}
	if observed, err := service.Observe(ctx, ca); err != nil || observed != input.Options.Request.PreviousLeaf {
		t.Fatal("helper predecessor TLS")
	}
	publisher, run, err := crashPublisher(ctx, service)
	if err != nil {
		t.Fatal("helper database binding")
	}
	if input.Point == "finished_sql" {
		publisher.Run = func(ctx context.Context, statement []byte) ([]byte, error) {
			response, err := run(ctx, statement)
			if err == nil && bytes.Contains(statement, []byte("public.finish_relay_authority_switch(")) {
				os.Exit(86)
			}
			return response, err
		}
	}
	host := &RelayAuthoritySnapshotHost{Options: input.Options, Service: service}
	host.checkpoint = func(point string) {
		if point == input.Point {
			os.Exit(86)
		}
	}
	_, _ = (relayauthority.Transition{Directory: input.Options.Directory, ServerName: service.binding.Config.ConsoleHost, Request: input.Options.Request, Host: host, Trust: publisher}).Run(ctx)
	t.Fatal("owned helper returned without its requested durable checkpoint")
}

func TestNativeAuthorityProcessRecovery(t *testing.T) {
	directory := os.Getenv("NETHUB_TEST_AUTHORITY_DIRECTORY")
	if directory == "" {
		t.Skip("requires isolated running authority process recovery fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("process acceptance requires protected root fixture")
	}
	project := os.Getenv("NETHUB_TEST_GUI_SQL_PROJECT")
	compose := os.Getenv("NETHUB_TEST_AUTHORITY_COMPOSE")
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()
	manifest, err := Load(directory)
	if err != nil || CheckFiles(directory) != nil {
		t.Fatal("confirmed process fixture")
	}
	if _, err := MaintainRelay(ctx, MaintenanceOptions{Directory: directory, Project: project, ComposeFile: compose}); err != nil {
		t.Fatal("create actual unchanged maintenance journal", err)
	}
	service, err := BindRelayAuthorityService(ctx, directory, project, compose, "")
	if err != nil {
		t.Fatal("process service fixture", err)
	}
	publisher, _, err := crashPublisher(ctx, service)
	if err != nil {
		t.Fatal("process database fixture", err)
	}
	current, err := publisher.Current(ctx)
	if err != nil || current == nil {
		t.Fatal("process fixture requires the preceding published trust acceptance")
	}
	before := map[string][]byte{}
	owners := expectedOwners()
	for _, path := range relayRuntimeFiles {
		owners[path] = 65532
	}
	owners["setup.json"] = 0
	for path, uid := range owners {
		raw, err := authorityRead(filepath.Join(directory, filepath.FromSlash(path)), uid, 32768)
		if err != nil {
			t.Fatal("baseline private files")
		}
		before[path] = raw
	}
	baselineTree, present, err := authorityTree(filepath.Join(directory, "secrets/issuer/maintenance"))
	if err != nil || !present || len(baselineTree) == 0 {
		t.Fatal("actual retained maintenance baseline")
	}
	root := filepath.Join(filepath.Dir(directory), "authority-process-recovery")
	if os.Mkdir(root, 0700) != nil {
		t.Fatal("private process recovery parent")
	}
	candidate := filepath.Join(root, "candidate")
	backup := filepath.Join(root, "candidate-backup")
	custody := filepath.Join(root, "custody.json")
	next, err := relayauthority.Prepare(candidate, manifest.Config.ConsoleHost, before["secrets/issuer/ca.pem"], before["secrets/issuer/ca-key.pem"], time.Now())
	if err != nil || relayauthority.Backup(candidate, backup, time.Now()) != nil {
		t.Fatal("process candidate backup")
	}
	if _, err := relayauthority.AcknowledgeBackup(candidate, backup, custody, relayauthority.CustodyPhrase, time.Now()); err != nil {
		t.Fatal("process fixture backup acknowledgement")
	}
	overlap, err := publisher.Publish(ctx, current.ID, string(before["secrets/issuer/ca.pem"])+string(next.Material.CA))
	if err != nil {
		t.Fatal("process overlap publication", err)
	}
	reportCrashFixtureTrust(t, ctx, directory, manifest, root, overlap)
	ids := func() map[string]string {
		t.Helper()
		result := map[string]string{}
		for _, name := range []string{"postgres", "nethub-web", "caddy", "nethub-authz", "frps"} {
			raw, err := service.command(ctx, append(append([]string{}, service.host.compose...), "ps", "--all", "--quiet", name)...)
			value := strings.TrimSpace(string(raw))
			if err != nil || !guiContainerID.MatchString(value) {
				t.Fatal("owned service identity unavailable")
			}
			result[name] = value
		}
		return result
	}
	unchanged := ids()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("owned test executable")
	}
	points := []string{"maintenance", "runtime/relay/relay-cert.pem", "runtime/relay/relay-key.pem", "runtime/trust/relay-ca.pem",
		"secrets/issuer/ca-key.pem", "secrets/issuer/ca.pem", "secrets/issuer/initial/relay-cert.pem", "secrets/issuer/initial/relay-key.pem", "setup.json", "reloaded", "finished_sql"}
	leasePath := filepath.Join(directory, "relay-operation.lock")
	leaseBefore, err := os.Stat(leasePath)
	if err != nil {
		t.Fatal("original shared lease inode")
	}
	for index, point := range points {
		if ctx.Err() != nil {
			t.Fatal("process recovery deadline exceeded")
		}
		opts := RelayAuthoritySnapshotOptions{Directory: directory, CandidateDirectory: candidate, CandidateBackup: backup, CustodyFile: custody, SuccessorBackup: filepath.Join(root, fmt.Sprintf("backup-%02d", index)), ServiceFingerprint: service.Fingerprint(),
			Request: relaytrust.SwitchRequest{ID: fmt.Sprintf("a1111111-1111-4111-8111-%012x", index+1), GenerationID: overlap.ID, PreviousRoot: next.Metadata.Previous, NextRoot: next.Metadata.Next, PreviousLeaf: authorityLeaf(before["runtime/relay/relay-cert.pem"]), NextLeaf: authorityLeaf(next.Material.Certificate)}}
		path := filepath.Join(root, fmt.Sprintf("input-%02d.json", index))
		if writePrivate(path, authorityJSON(authorityCrashInput{Options: opts, Project: project, Compose: compose, Point: point})) != nil || authoritySyncDirectory(root) != nil {
			t.Fatal("persist private child input")
		}
		childCtx, childCancel := context.WithTimeout(ctx, 70*time.Second)
		command := exec.CommandContext(childCtx, executable, "-test.run=^TestAuthorityCrashHelper$", "-test.timeout=65s")
		command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C", "NETHUB_AUTHORITY_CRASH_INPUT=" + path}
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		command.Cancel = func() error {
			if command.Process == nil {
				return nil
			}
			return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		command.WaitDelay = 2 * time.Second
		output := guiOutput{limit: 65536}
		command.Stdout = &output
		command.Stderr = &output
		childErr := command.Run()
		childCancel()
		// Keep diagnostics private and bounded, never echo child stdout on failure.
		if writePrivate(filepath.Join(root, fmt.Sprintf("child-%02d.log", index)), output.Bytes()) != nil {
			t.Fatal("retain private child result")
		}
		exit, ok := childErr.(*exec.ExitError)
		if !ok || exit.ExitCode() != 86 || output.overflow {
			t.Fatal("owned child did not stop at requested checkpoint", point)
		}
		leaseAfter, err := os.Stat(leasePath)
		if err != nil || !os.SameFile(leaseBefore, leaseAfter) {
			t.Fatal("process death replaced shared lease inode")
		}
		acquired, err := hostlease.Acquire(leasePath)
		if err != nil {
			t.Fatal("process death did not release original lease")
		}
		acquired.Close()
		if relayauthority.CheckNoPendingTransition(directory) == nil {
			t.Fatal("process death reopened ordinary maintenance")
		}
		receipt, err := publisher.ReadSwitch(ctx, opts.Request.ID)
		if err != nil {
			t.Fatal("retained real database intent", point, err)
		}
		expectedPhase := "pending"
		if point == "finished_sql" {
			expectedPhase = "committed"
		}
		if receipt.Phase != expectedPhase {
			t.Fatal("unexpected real database phase after process death", point, receipt.Phase)
		}
		beforeResume := ids()
		state, resumeErr := ResumeBoundRelayAuthorityTransition(ctx, directory, opts.Request.ID, project, compose)
		terminal := "rolled_back"
		if point == "finished_sql" {
			terminal = "committed"
		}
		if state.Phase != terminal || terminal == "committed" && resumeErr != nil {
			t.Fatal("real process recovery failed", point, state.Phase, resumeErr)
		}
		receipt, err = publisher.ReadSwitch(ctx, opts.Request.ID)
		if err != nil || receipt.Phase != terminal || receipt.ObservedLeaf == nil {
			t.Fatal("real process recovery did not resolve matching database receipt", point, err)
		}
		if CheckFiles(directory) != nil || relayauthority.CheckNoPendingTransition(directory) != nil {
			t.Fatal("recovered authority/backup/journal invalid", point)
		}
		afterResume := ids()
		for _, name := range []string{"postgres", "nethub-web", "caddy"} {
			if afterResume[name] != unchanged[name] {
				t.Fatal("recovery changed unrelated service", name)
			}
		}
		if terminal == "rolled_back" {
			for path, raw := range before {
				actual, err := authorityRead(filepath.Join(directory, filepath.FromSlash(path)), owners[path], 32768)
				if err != nil || !bytes.Equal(actual, raw) {
					t.Fatal("process rollback changed baseline file", point, path)
				}
			}
			tree, present, err := authorityTree(filepath.Join(directory, "secrets/issuer/maintenance"))
			if err != nil || !present || !bytes.Equal(authorityJSON(tree), authorityJSON(baselineTree)) {
				t.Fatal("process rollback changed retained maintenance", point)
			}
			observed, err := relaycert.Observe(ctx, netip.MustParseAddrPort("127.0.0.1:7000"), manifest.Config.ConsoleHost, before["secrets/issuer/ca.pem"])
			if err != nil || hex.EncodeToString(observed[:]) != opts.Request.PreviousLeaf {
				t.Fatal("old actual TLS not restored", point)
			}
		} else {
			for name, id := range beforeResume {
				if afterResume[name] != id {
					t.Fatal("committed lost reply replayed service reload", name)
				}
			}
			if *receipt.ObservedLeaf != opts.Request.NextLeaf {
				t.Fatal("wrong actual committed leaf")
			}
		}
		retry, retryErr := ResumeBoundRelayAuthorityTransition(ctx, directory, opts.Request.ID, project, compose)
		if retryErr != nil || retry.Phase != terminal || !retry.UpdatedAt.Equal(state.UpdatedAt) {
			t.Fatal("terminal process retry changed decision", point, retryErr)
		}
		afterRetry := ids()
		for name, id := range afterResume {
			if afterRetry[name] != id {
				t.Fatal("terminal retry recreated service", name)
			}
		}
		t.Log("Recovered owned process exit at durable checkpoint", point)
	}
	t.Log("Actual process recovery passed ten file/journal/reload exits with exact old-state rollback and one committed SQL-response exit without write/reload replay; real PostgreSQL, service TLS and cleanup-scoped backups, no native application")
}

func reportCrashFixtureTrust(t *testing.T, ctx context.Context, directory string, manifest Manifest, root string, g *relaytrust.Generation) {
	t.Helper()
	prefix, err := netip.ParsePrefix(manifest.Config.NetworkSubnet)
	if err != nil {
		t.Fatal("private fixture subnet")
	}
	endpoint := net.JoinHostPort(prefix.Addr().Next().Next().Next().Next().String(), "8081")
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for index := range 2 {
		raw, err := authorityRead(filepath.Join(filepath.Dir(directory), "relay-test", fmt.Sprintf("assignment%d.json", index)), 0, 65536)
		var assignment protocol.EnrollResponse
		if err != nil || json.Unmarshal(raw, &assignment) != nil || !protocol.ValidDeviceSecret(assignment.DeviceSecret) {
			t.Fatal("private enrolled fixture identity")
		}
		post := func(action string, input any) []byte {
			t.Helper()
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal("fixture request")
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+endpoint+"/api/v1/devices/relay-trust/"+action, bytes.NewReader(raw))
			if err != nil {
				t.Fatal("fixture request construction")
			}
			request.Host = manifest.Config.ConsoleHost
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+assignment.DeviceSecret)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("private authenticated trust request")
			}
			defer response.Body.Close()
			body, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxBodyBytes+1))
			if err != nil || len(body) > protocol.MaxBodyBytes || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(body, []byte(assignment.DeviceSecret)) {
				t.Fatal("compiled trust response", response.StatusCode)
			}
			return body
		}
		identity := protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: assignment.DeviceID}
		var settings protocol.RelayTrustSettings
		if json.Unmarshal(post("settings", identity), &settings) != nil || settings.Desired == nil || settings.DeviceID != identity.DeviceID || settings.Desired.ID != g.ID {
			t.Fatal("process fixture current trust")
		}
		validated, err := relaytrust.Parse(settings.Desired.CAPEM, time.Now())
		if err != nil || validated.Fingerprint() != g.Bundle().Fingerprint() || writePrivate(filepath.Join(root, fmt.Sprintf("client-trust-%d.pem", index)), []byte(validated.PEM())) != nil {
			t.Fatal("independent fixture trust persistence")
		}
		input := protocol.RelayTrustAppliedRequest{Identity: identity, GenerationID: g.ID, Generation: g.Number, Fingerprint: validated.Fingerprint()}
		var applied protocol.RelayTrustAppliedResponse
		if json.Unmarshal(post("applied", input), &applied) != nil || applied.Validate() != nil || applied.RelayTrustAppliedRequest != input {
			t.Fatal("compiled authenticated process fixture acknowledgement")
		}
	}
}
