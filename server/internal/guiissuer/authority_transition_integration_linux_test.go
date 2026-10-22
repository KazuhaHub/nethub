package guiissuer_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"github.com/KazuhaHub/nethub/server/internal/relaycert"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
	"github.com/KazuhaHub/nethub/server/internal/setup"
)

func TestNativeRelayAuthorityTransition(t *testing.T) {
	directory := os.Getenv("NETHUB_TEST_AUTHORITY_DIRECTORY")
	if directory == "" {
		t.Skip("requires isolated running Compose authority transition fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("authority transition requires protected root fixture")
	}
	project := os.Getenv("NETHUB_TEST_GUI_SQL_PROJECT")
	override := os.Getenv("NETHUB_TEST_AUTHORITY_COMPOSE")
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	manifest, err := setup.Load(directory)
	if err != nil || setup.CheckFiles(directory) != nil {
		t.Fatal("initial confirmed authority fixture")
	}
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("private fixture file unavailable")
		}
		return raw
	}
	before := map[string][]byte{}
	for _, file := range manifest.Files {
		before[file.Path] = read(filepath.Join(directory, filepath.FromSlash(file.Path)))
	}
	for _, path := range []string{"setup.json", "runtime/relay/relay-cert.pem", "runtime/relay/relay-key.pem", "runtime/trust/relay-ca.pem"} {
		before[path] = read(filepath.Join(directory, filepath.FromSlash(path)))
	}
	serviceID := func(name string) string {
		t.Helper()
		command := exec.CommandContext(ctx, "/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "compose", "--project-name", project, "--file", filepath.Join(directory, "docker-compose.yml"), "--file", filepath.Join(directory, "docker-compose.override.yml"), "--file", override, "ps", "--all", "--quiet", name)
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
		raw, err := command.Output()
		id := strings.TrimSpace(string(raw))
		if err != nil || len(id) != 64 {
			t.Fatal("bound cancellation service identity unavailable")
		}
		return id
	}
	services := map[string]string{}
	for _, name := range []string{"postgres", "nethub-web", "caddy", "nethub-authz", "frps"} {
		services[name] = serviceID(name)
	}
	leaf := read(filepath.Join(directory, "runtime/relay/relay-cert.pem"))
	fingerprint := func(raw []byte) string {
		t.Helper()
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatal("fixture certificate")
		}
		value := sha256.Sum256(block.Bytes)
		return hex.EncodeToString(value[:])
	}
	run, err := guiissuer.NewDockerSQLRunner(guiissuer.DockerBinding{ContainerID: os.Getenv("NETHUB_TEST_GUI_SQL_CONTAINER"), ImageID: os.Getenv("NETHUB_TEST_GUI_SQL_IMAGE"), Project: project})
	if err != nil {
		t.Fatal("private database fixture identity")
	}
	publisher := &relaytrust.Publisher{Run: relaytrust.SQLRunner(run), ServerName: manifest.Config.ConsoleHost}
	if current, err := publisher.Current(ctx); err != nil || current != nil {
		t.Fatal("fixture expected fresh public trust history", err)
	}
	first, err := publisher.Publish(ctx, "", string(before["secrets/issuer/ca.pem"]))
	if err != nil {
		t.Fatal("fixture initial public trust publication", err)
	}
	// The active successor backup must survive this test until the outer owned
	// deployment cleanup; t.TempDir would remove it while later checks still run.
	root := filepath.Join(filepath.Dir(directory), "authority-transition-test")
	if os.Mkdir(root, 0700) != nil {
		t.Fatal("private fixture parent")
	}
	candidate := filepath.Join(root, "candidate")
	backup := filepath.Join(root, "candidate-backup")
	custody := filepath.Join(root, "custody.json")
	next, err := relayauthority.Prepare(candidate, manifest.Config.ConsoleHost, before["secrets/issuer/ca.pem"], before["secrets/issuer/ca-key.pem"], time.Now())
	if err != nil || relayauthority.Backup(candidate, backup, time.Now()) != nil {
		t.Fatal("fixture independent candidate backup")
	}
	if _, err := relayauthority.AcknowledgeBackup(candidate, backup, custody, relayauthority.CustodyPhrase, time.Now()); err != nil {
		t.Fatal("fixture explicit backup acknowledgement")
	}
	overlap, err := publisher.Publish(ctx, first.ID, string(before["secrets/issuer/ca.pem"])+string(next.Material.CA))
	if err != nil {
		t.Fatal("fixture candidate overlap publication", err)
	}

	// These are authenticated compiled API reports after independent fixture file
	// validation. They are not evidence that a native router installed this trust.
	prefix, err := netip.ParsePrefix(manifest.Config.NetworkSubnet)
	if err != nil {
		t.Fatal("fixture subnet")
	}
	authz := prefix.Addr().Next().Next().Next().Next()
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	assignments := make([]protocol.EnrollResponse, 2)
	for i := range assignments {
		if json.Unmarshal(read(filepath.Join(filepath.Dir(directory), "relay-test", "assignment"+strconv.Itoa(i)+".json")), &assignments[i]) != nil || !protocol.ValidDeviceSecret(assignments[i].DeviceSecret) {
			t.Fatal("fixture enrollment credentials unavailable")
		}
	}
	post := func(assignment protocol.EnrollResponse, action string, input any) []byte {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal("fixture request")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+net.JoinHostPort(authz.String(), "8081")+"/api/v1/devices/relay-trust/"+action, bytes.NewReader(raw))
		if err != nil {
			t.Fatal("fixture request construction")
		}
		request.Host = manifest.Config.ConsoleHost
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+assignment.DeviceSecret)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("private authenticated trust request failed")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxBodyBytes+1))
		if err != nil || len(body) > protocol.MaxBodyBytes || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(body, []byte(assignment.DeviceSecret)) {
			t.Fatal("authenticated trust response refused or leaked", response.StatusCode)
		}
		return body
	}
	report := func(g *relaytrust.Generation) {
		t.Helper()
		for i, assignment := range assignments {
			identity := protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: assignment.DeviceID}
			var settings protocol.RelayTrustSettings
			if json.Unmarshal(post(assignment, "settings", identity), &settings) != nil || settings.DeviceID != assignment.DeviceID || settings.Desired == nil || settings.Desired.ID != g.ID || settings.Desired.Generation != g.Number || settings.Desired.ServerName != manifest.Config.ConsoleHost || settings.Desired.Fingerprint != g.Bundle().Fingerprint() {
				t.Fatal("compiled API delivered wrong current trust")
			}
			validated, err := relaytrust.Parse(settings.Desired.CAPEM, time.Now())
			if err != nil || validated.Fingerprint() != g.Bundle().Fingerprint() || os.WriteFile(filepath.Join(root, "client-trust-"+strconv.Itoa(i)+".pem"), []byte(validated.PEM()), 0600) != nil {
				t.Fatal("independent fixture trust validation/persistence")
			}
			input := protocol.RelayTrustAppliedRequest{Identity: identity, GenerationID: g.ID, Generation: g.Number, Fingerprint: validated.Fingerprint()}
			var accepted protocol.RelayTrustAppliedResponse
			if json.Unmarshal(post(assignment, "applied", input), &accepted) != nil || accepted.Validate() != nil || accepted.RelayTrustAppliedRequest != input {
				t.Fatal("compiled authenticated trust report failed")
			}
		}
	}
	service, err := setup.BindRelayAuthorityService(ctx, directory, project, override, "")
	if err != nil {
		t.Fatal("initial bound deployment service", err)
	}
	opts := setup.RelayAuthoritySnapshotOptions{Directory: directory, CandidateDirectory: candidate, CandidateBackup: backup, CustodyFile: custody, SuccessorBackup: filepath.Join(root, "successor-full-backup"), ServiceFingerprint: service.Fingerprint(),
		Request: relaytrust.SwitchRequest{ID: "54dcc6c9-093f-4d76-8b4d-f27836cfaec5", GenerationID: overlap.ID, PreviousRoot: next.Metadata.Previous, NextRoot: next.Metadata.Next, PreviousLeaf: fingerprint(leaf), NextLeaf: fingerprint(next.Material.Certificate)}}
	// Without current application reports admission must refuse the prepared
	// operation. Cancellation must preserve that history rather than erase it.
	abortOpts := opts
	abortOpts.Request.ID = "a12cfec0-5907-4e31-99ea-ab0061a01ac5"
	abortOpts.SuccessorBackup = filepath.Join(root, "cancelled-successor-backup")
	prepared, err := setup.RunBoundRelayAuthorityTransition(ctx, abortOpts, project, override)
	if err == nil || prepared.Phase != "prepared" || relayauthority.CheckNoPendingTransition(directory) == nil {
		t.Fatal("refused preparation did not retain maintenance exclusion", err)
	}
	aborted, err := setup.AbortBoundRelayAuthorityTransition(ctx, directory, abortOpts.Request.ID, project, override)
	if err != nil || aborted.Phase != "aborted" || aborted.Cancellation == nil || setup.CheckFiles(directory) != nil || relayauthority.CheckNoPendingTransition(directory) != nil {
		t.Fatal("bound prepared-operation cancellation failed", err)
	}
	cancellation, err := publisher.ReadCancellation(ctx, abortOpts.Request.ID)
	if err != nil || cancellation.IntentDigest != aborted.IntentDigest || !cancellation.CancelledAt.Equal(aborted.Cancellation.CancelledAt) {
		t.Fatal("bound cancellation did not retain exact database receipt", err)
	}
	retried, err := setup.AbortBoundRelayAuthorityTransition(ctx, directory, abortOpts.Request.ID, project, override)
	if err != nil || !retried.UpdatedAt.Equal(aborted.UpdatedAt) || !retried.Cancellation.CancelledAt.Equal(cancellation.CancelledAt) {
		t.Fatal("bound cancellation retry changed timestamps", err)
	}
	for path, raw := range before {
		if !bytes.Equal(read(filepath.Join(directory, filepath.FromSlash(path))), raw) {
			t.Fatal("cancellation changed original credentials")
		}
	}
	observedBefore, err := observeFixtureRelay(ctx, netip.MustParseAddrPort("127.0.0.1:7000"), manifest.Config.ConsoleHost, before["secrets/issuer/ca.pem"])
	if err != nil || observedBefore != opts.Request.PreviousLeaf {
		t.Fatal("cancellation changed actual original TLS", err)
	}
	report(overlap)
	if _, err := publisher.BeginSwitch(ctx, abortOpts.Request); err == nil {
		t.Fatal("cancelled operation admitted after device reports")
	}
	if _, err := setup.RunBoundRelayAuthorityTransition(ctx, abortOpts, project, override); err == nil {
		t.Fatal("cancelled host operation replayed")
	}
	for name, id := range services {
		if serviceID(name) != id {
			t.Fatal("cancellation or refused replay recreated service", name)
		}
	}
	wrongBaseline := opts
	wrongBaseline.Request.PreviousLeaf = opts.Request.NextRoot
	if _, err := setup.RunBoundRelayAuthorityTransition(ctx, wrongBaseline, project, override); err == nil {
		t.Fatal("unobserved predecessor leaf admitted")
	}
	if _, err := os.Lstat(filepath.Join(directory, "authority-transitions", opts.Request.ID)); !os.IsNotExist(err) {
		t.Fatal("refused predecessor created a transition journal")
	}
	state, err := setup.RunBoundRelayAuthorityTransition(ctx, opts, project, override)
	if err != nil || state.Phase != "committed" {
		t.Fatal("combined bound authority transition failed", state.Phase, err)
	}
	receipt, err := publisher.ReadSwitch(ctx, opts.Request.ID)
	if err != nil || receipt.Phase != "committed" || receipt.ObservedLeaf == nil || *receipt.ObservedLeaf != opts.Request.NextLeaf {
		t.Fatal("combined real database terminal identity", err)
	}
	if setup.CheckFiles(directory) != nil || relayauthority.CheckNoPendingTransition(directory) != nil {
		t.Fatal("combined authority/backup/journal validation")
	}
	if !bytes.Equal(read(filepath.Join(directory, "secrets/issuer/ca.pem")), next.Material.CA) {
		t.Fatal("active authority did not change")
	}
	for _, file := range manifest.Files {
		if file.Path == "secrets/issuer/ca.pem" || file.Path == "secrets/issuer/ca-key.pem" || file.Path == "secrets/issuer/initial/relay-cert.pem" || file.Path == "secrets/issuer/initial/relay-key.pem" {
			continue
		}
		if !bytes.Equal(read(filepath.Join(directory, filepath.FromSlash(file.Path))), before[file.Path]) {
			t.Fatal("combined transition changed unrelated credentials")
		}
	}
	resumed, err := setup.ResumeBoundRelayAuthorityTransition(ctx, directory, opts.Request.ID, project, override)
	if err != nil || resumed.Phase != "committed" || !resumed.UpdatedAt.Equal(state.UpdatedAt) {
		t.Fatal("completed operation did not resume exact retained identity", err)
	}
	final, err := publisher.Publish(ctx, overlap.ID, string(next.Material.CA))
	if err != nil {
		t.Fatal("applied-overlap root retirement after actual signer switch", err)
	}
	report(final)
	// Fresh control TLS must accept the successor and refuse the retired root.
	endpoint := netip.MustParseAddrPort("127.0.0.1:7000")
	observed, err := observeFixtureRelay(ctx, endpoint, manifest.Config.ConsoleHost, next.Material.CA)
	if err != nil || observed != opts.Request.NextLeaf {
		t.Fatal("actual successor TLS identity", err)
	}
	if _, err := observeFixtureRelay(ctx, endpoint, manifest.Config.ConsoleHost, before["secrets/issuer/ca.pem"]); err == nil {
		t.Fatal("retired authority still accepted actual served relay")
	}
	t.Log("Combined authority transition passed authenticated compiled trust reports, real PostgreSQL fence, exact files/backups/maintenance, actual authz/frps reload, retained-request resume, successor TLS and retired-root refusal; no native trust application or per-write process termination")
	t.Log("Bound authority abort passed refused preparation, serialized cancellation, unchanged original files/TLS/services, exact retry and fresh-operation reprepare; no partial-initialization or expiry recovery")
}

func observeFixtureRelay(ctx context.Context, endpoint netip.AddrPort, name string, ca []byte) (string, error) {
	value, err := relaycert.Observe(ctx, endpoint, name, ca)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
