package guiacme_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiacme"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/KazuhaHub/nethub/server/internal/http01"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relaycert"
	"github.com/KazuhaHub/nethub/server/internal/setup"
)

// This opt-in fixture starts only nonce-owned, portless Compose PostgreSQL and
// private CA/proxy resources. Its outer deployment harness arms an independent
// exact-resource cleanup guard before entering this test.
func TestPebbleProtectedHostIssuer(t *testing.T) {
	testPebbleProtectedHostIssuer(t, false, false)
}

func TestPebbleProtectedHostIssuerRenewal(t *testing.T) {
	testPebbleProtectedHostIssuer(t, true, false)
}

func TestPebbleProtectedHostAccountProvisioning(t *testing.T) {
	testPebbleProtectedHostIssuer(t, false, true)
}

func testPebbleProtectedHostIssuer(t *testing.T, renewal, provisionAccount bool) {
	binary, image := os.Getenv("NETHUB_HOST_ISSUER_BINARY"), os.Getenv("NETHUB_HOST_POSTGRES_IMAGE")
	if binary == "" || image == "" {
		t.Skip("requires the independently guarded host-command fixture")
	}
	nonce := os.Getenv("NETHUB_GUIACME_TEST_NONCE")
	if os.Geteuid() != 0 || !regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(nonce) || !filepath.IsAbs(binary) {
		t.Fatal("invalid guarded host fixture")
	}
	project := "nethub-stack-test-" + nonce
	container := project + "-postgres"
	timer := "nethub-host-test-" + nonce
	command := func(input []byte, program string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if program == "/usr/bin/docker" {
			args = append([]string{"--host", "unix:///var/run/docker.sock"}, args...)
		}
		c := exec.CommandContext(ctx, program, args...)
		c.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
		c.Stdin = bytes.NewReader(input)
		return c.Output()
	}
	must := func(input []byte, program string, args ...string) []byte {
		t.Helper()
		data, err := command(input, program, args...)
		if err != nil {
			t.Fatalf("owned host fixture command failed: %s", filepath.Base(program))
		}
		return bytes.TrimSpace(data)
	}
	fixture := guiacme.RunPebbleHostFixture
	if renewal {
		fixture = guiacme.RunPebbleHostRenewalFixture
	}
	fixture(t, func(files guiacme.PebbleHostFiles, account *guiacme.AccountStore, publisher *http01.Publisher, roots *x509.CertPool, csr []byte, public string) guiacme.Order {
		write := func(path string, data []byte) {
			t.Helper()
			if os.WriteFile(path, data, 0600) != nil {
				t.Fatal("private host fixture file")
			}
		}
		writeJSON := func(path string, value any) {
			t.Helper()
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal("host fixture encoding")
			}
			write(path, data)
		}
		source := filepath.Join(files.Stage, "source")
		for _, path := range []string{"deploy/Dockerfile", "deploy/images/caddy/Dockerfile", "deploy/images/postgres/Dockerfile", "deploy/images/frps/Dockerfile"} {
			name := filepath.Join(source, path)
			if os.MkdirAll(filepath.Dir(name), 0700) != nil {
				t.Fatal("host fixture source directory")
			}
			write(name, []byte("FROM scratch\n"))
		}
		directory, err := setup.Generate(filepath.Join(files.Stage, "deployment"), setup.Config{ConsoleHost: "console.example.test", DeviceDomain: "devices.example.test", SourceDirectory: source, NetworkSubnet: "172.30.87.0/24"})
		if err != nil {
			t.Fatal("isolated deployment generation")
		}
		backup, err := setup.Backup(directory, filepath.Join(files.Stage, "independent-backup"))
		if err != nil || setup.Confirm(directory, backup, setup.BackupPhrase) != nil {
			t.Fatal("independent disposable authority backup")
		}
		override := filepath.Join(directory, "fixture.json")
		writeJSON(override, map[string]any{"services": map[string]any{"postgres": map[string]any{
			"image": image, "container_name": container, "restart": "no", "mem_limit": "512m", "cpus": "1.0",
			"labels": map[string]string{"org.nethub.gui-issuer-test": project, "org.nethub.guiacme-test": nonce},
		}}})
		compose := []string{"compose", "--project-name", project, "--file", filepath.Join(directory, "docker-compose.yml"), "--file", filepath.Join(directory, "docker-compose.override.yml"), "--file", override}
		t.Cleanup(func() {
			command(nil, "/usr/bin/systemctl", "stop", timer+"-issuer.service")
			if err := os.Remove("/run/systemd/system/" + timer + "-issuer.service"); err != nil && !os.IsNotExist(err) {
				t.Error("owned host issuer unit removal")
			}
			command(nil, "/usr/bin/systemctl", "stop", timer+".timer", timer+".service")
			for _, suffix := range []string{".timer", ".service"} {
				if err := os.Remove("/run/systemd/system/" + timer + suffix); err != nil && !os.IsNotExist(err) {
					t.Error("owned host timer removal")
				}
			}
			command(nil, "/usr/bin/systemctl", "daemon-reload")
			if _, err := command(nil, "/usr/bin/docker", append(compose, "down", "--volumes", "--timeout", "3")...); err != nil {
				t.Error("owned Compose cleanup; independent guard remains authoritative")
			}
		})
		must(nil, "/usr/bin/docker", append(compose, "up", "--detach", "--no-build", "--pull", "never", "postgres")...)
		id := string(must(nil, "/usr/bin/docker", "inspect", "--format", "{{.Id}}", container))
		imageID := string(must(nil, "/usr/bin/docker", "inspect", "--format", "{{.Image}}", id))
		binding := guiissuer.DockerBinding{ContainerID: id, ImageID: imageID, Project: project}
		run, err := guiissuer.NewDockerSQLRunner(binding)
		if err != nil {
			t.Fatal("owned database runner")
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			// The bootstrap temporary server has no TCP listener. The next
			// owner-authenticated migration verifies roles and the actual database.
			if _, err = command(nil, "/usr/bin/docker", "exec", id, "pg_isready", "--host", "127.0.0.1", "--username", "postgres", "--dbname", "nethub"); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("host fixture database readiness bound")
			}
			time.Sleep(200 * time.Millisecond)
		}
		must(nil, "/usr/bin/docker", "cp", binary, id+":/tmp/nethub-host-fixture")
		must(nil, "/usr/bin/docker", "exec", id, "chmod", "0755", "/tmp/nethub-host-fixture")
		must(nil, "/usr/bin/docker", "exec", "--user", "postgres", id, "/tmp/nethub-host-fixture", "migrate", "--host", "127.0.0.1", "--password-file", "/run/secrets/pg_nethub_owner", "--sslmode", "disable")
		policyFile := filepath.Join(files.Stage, "http01.json")
		writeJSON(policyFile, http01.FileConfig{Version: 1, PublicDirectory: filepath.Join(files.Stage, "http-public"), StateDirectory: filepath.Join(files.Stage, "http-private"), DeviceDomain: "devices.example.test", ExcludedHosts: []string{"console.example.test"}})
		issuerFile := filepath.Join(files.Stage, "gui-issuer.json")
		writeJSON(issuerFile, setup.GUIIssuerPolicy{Version: 1, AccountDirectory: files.AccountDirectory, DirectoryURL: files.DirectoryURL, ContactEmail: "admin@example.test", AdditionalOrigins: []string{}, APIRootsFile: files.APIRootsFile, CertificateRootsFile: files.CertificateRootsFile, HTTPPolicyFile: policyFile, CleanupTimer: timer + ".timer"})
		// This fixture lives under a private temporary home directory. The
		// separately accepted shipped unit masks home; this fixture unit has
		// explicit paths solely to exercise the host's genuine timer/receipt gate.
		write("/run/systemd/system/"+timer+".service", []byte("[Service]\nType=oneshot\nExecStart="+binary+" certificates cleanup-http01 --config-file "+policyFile+"\nPrivateNetwork=true\nNoNewPrivileges=true\n"))
		write("/run/systemd/system/"+timer+".timer", []byte("[Timer]\nOnActiveSec=1s\nOnUnitInactiveSec=15s\n"))
		must(nil, "/usr/bin/systemctl", "daemon-reload")
		must(nil, "/usr/bin/systemctl", "start", timer+".service", timer+".timer")
		args := []string{"certificates", "issue-gui", "--directory", directory, "--project-name", project, "--config-file", issuerFile, "--compose-file", override}
		issuerCommand := func() ([]byte, error) {
			// Periodic cleanup may briefly hold the namespace lock. The CLI's
			// explicit busy skip is not successful admission or a policy failure.
			until := time.Now().Add(15 * time.Second)
			for {
				data, err := command(nil, binary, args...)
				if err != nil || strings.TrimSpace(string(data)) != "GUI issuer already running or namespace busy; skipped" || time.Now().After(until) {
					return data, err
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
		invoke := func() setup.GUIIssuerResult {
			t.Helper()
			data, err := issuerCommand()
			if err != nil {
				t.Fatal("host issuer command failed")
			}
			var result setup.GUIIssuerResult
			if json.Unmarshal(data, &result) != nil {
				t.Fatal("host issuer returned non-JSON state")
			}
			return result
		}
		if invoke().State != "idle" {
			t.Fatal("clean host fixture was not idle")
		}
		policyBytes, err := os.ReadFile(issuerFile)
		if err != nil {
			t.Fatal("private issuer fixture policy")
		}
		var missingAccount setup.GUIIssuerPolicy
		if json.Unmarshal(policyBytes, &missingAccount) != nil {
			t.Fatal("private issuer fixture policy encoding")
		}
		missingAccount.AccountDirectory = filepath.Join(files.Stage, "uninitialized-account")
		writeJSON(issuerFile, missingAccount)
		if _, err := issuerCommand(); err == nil {
			t.Fatal("host issuer accepted an uninitialized account")
		}
		if _, err := os.Lstat(missingAccount.AccountDirectory); !os.IsNotExist(err) {
			t.Fatal("ordinary host work initialized or replaced account state")
		}
		write(issuerFile, policyBytes)
		must(nil, "/usr/bin/systemctl", "stop", timer+".timer", timer+".service")
		if _, err := issuerCommand(); err == nil {
			t.Fatal("issuer accepted a stopped independent cleanup timer")
		}
		must(nil, "/usr/bin/systemctl", "start", timer+".timer")
		activeAccountDirectory := files.AccountDirectory
		if provisionAccount {
			var policy setup.GUIIssuerPolicy
			if json.Unmarshal(policyBytes, &policy) != nil {
				t.Fatal("account policy fixture")
			}
			policy.AccountDirectory = filepath.Join(files.Stage, "operator-account")
			writeJSON(issuerFile, policy)
			accountArgs := func(action string, extra ...string) []string {
				return append([]string{"certificates", "account", action, "--directory", directory, "--config-file", issuerFile}, extra...)
			}
			accountCommand := func(action string, extra ...string) setup.GUIAccountResult {
				t.Helper()
				data := must(nil, binary, accountArgs(action, extra...)...)
				var result setup.GUIAccountResult
				if json.Unmarshal(data, &result) != nil || result.State == "" {
					t.Fatal("account command returned invalid status")
				}
				return result
			}
			if _, err := command(nil, binary, accountArgs("lookup")...); err == nil {
				t.Fatal("ordinary lookup initialized missing account")
			}
			if _, err := os.Lstat(policy.AccountDirectory); !os.IsNotExist(err) {
				t.Fatal("missing lookup created account directory")
			}
			if accountCommand("initialize").State != "initialized" {
				t.Fatal("offline account initialization failed")
			}
			backup := filepath.Join(files.Stage, "operator-account-backup")
			if accountCommand("backup", "--backup-directory", backup).State != "backed_up" {
				t.Fatal("account backup failed")
			}
			if accountCommand("verify-backup", "--backup-directory", backup).State != "backup_verified" {
				t.Fatal("account backup verification failed")
			}
			overlap := filepath.Join(directory, "runtime/forbidden-backup")
			if _, err := command(nil, binary, accountArgs("backup", "--backup-directory", overlap)...); err == nil {
				t.Fatal("account key backup allowed in runtime namespace")
			}
			if _, err := os.Lstat(overlap); !os.IsNotExist(err) {
				t.Fatal("forbidden backup created state")
			}
			consentFile := filepath.Join(files.Stage, "operator-consent.json")
			writeJSON(consentFile, map[string]string{"accepted_terms_reference": "https://terms.example.test/outdated"})
			registration := []string{"--backup-directory", backup, "--terms-file", consentFile, "--allow-create"}
			if _, err := command(nil, binary, accountArgs("register", registration...)...); err == nil {
				t.Fatal("outdated terms registered account")
			}
			review := accountCommand("terms")
			if review.State != "review_terms" || review.TermsReference == nil {
				t.Fatal("fresh terms review unavailable")
			}
			// This explicitly consents only to the disposable private test CA.
			writeJSON(consentFile, map[string]string{"accepted_terms_reference": *review.TermsReference})
			if _, err := command(nil, binary, accountArgs("register", "--terms-file", consentFile, "--allow-create")...); err == nil {
				t.Fatal("registration without backup accepted")
			}
			if accountCommand("register", registration...).State != "registered" {
				t.Fatal("explicit private registration failed")
			}
			if accountCommand("register", registration...).State != "registered" {
				t.Fatal("registration retry failed")
			}
			registered, err := os.ReadFile(filepath.Join(policy.AccountDirectory, "account.json"))
			if err != nil {
				t.Fatal("registered private state unavailable")
			}
			var original struct {
				URI string `json:"account_uri"`
			}
			if json.Unmarshal(registered, &original) != nil || original.URI == "" {
				t.Fatal("registered account identity missing")
			}
			policy.AccountDirectory = filepath.Join(files.Stage, "operator-account-restored")
			writeJSON(issuerFile, policy)
			if accountCommand("restore", "--backup-directory", backup).State != "restored" {
				t.Fatal("pre-registration backup recovery failed")
			}
			if accountCommand("lookup").State != "registered" {
				t.Fatal("same-key account lookup recovery failed")
			}
			restored, err := os.ReadFile(filepath.Join(policy.AccountDirectory, "account.json"))
			if err != nil {
				t.Fatal("restored private state unavailable")
			}
			var recovered struct {
				URI string `json:"account_uri"`
			}
			if json.Unmarshal(restored, &recovered) != nil || recovered.URI != original.URI {
				t.Fatal("restore lookup changed account identity")
			}
			activeAccountDirectory = policy.AccountDirectory
			t.Log("Protected account commands passed offline initialization, verified immutable backup, runtime-overlap refusal, fresh terms review, outdated/missing-backup consent refusal, explicit private-CA registration retry and original-account recovery from pre-registration backup")
		}
		client := enrollHostDevice(t, directory, nonce, binding, run, must)
		requestID, host := client.settings.Request.RequestID, client.settings.AssignedHost
		csr = client.csr
		issuedInput := protocol.CertificateIssuedRequest{Identity: client.settings.Identity, RequestID: requestID, CSRFingerprint: client.settings.Request.CSRFingerprint}
		status, body := client.post("issued", issuedInput)
		var pending protocol.CertificateDelivery
		if status != 200 || json.Unmarshal(body, &pending) != nil || pending.Validate() != nil || pending.Issued != nil {
			t.Fatal("fresh enrolled request did not start with pending delivery", status)
		}
		unitBytes, err := os.ReadFile(os.Getenv("NETHUB_HOST_ISSUER_UNIT"))
		if err != nil {
			t.Fatal("requires the exact checked-in issuer service template")
		}
		unit := string(unitBytes)
		for old, replacement := range map[string]string{
			"/usr/local/libexec/nethub":   binary,
			"/srv/nethub-deployment":      directory,
			"--project-name nethub":       "--project-name " + project,
			"/etc/nethub/gui-issuer.json": issuerFile + " --compose-file " + override,
			"/var/lib/nethub-gui-acme":    activeAccountDirectory,
			"/srv/nethub-http01":          filepath.Join(files.Stage, "http-public"),
			"/var/lib/nethub-http01":      filepath.Join(files.Stage, "http-private"),
			"nethub-http01-cleanup":       timer,
			"ProtectHome=true":            "ProtectHome=read-only",
		} {
			if !strings.Contains(unit, old) {
				t.Fatal("issuer fixture template drift")
			}
			unit = strings.ReplaceAll(unit, old, replacement)
		}
		write("/run/systemd/system/"+timer+"-issuer.service", []byte(unit))
		must(nil, "/usr/bin/systemctl", "daemon-reload")
		must(nil, "/usr/bin/systemctl", "start", timer+"-issuer.service")
		for property, expected := range map[string]string{"Result": "success", "ExecMainStatus": "0", "ProtectSystem": "strict", "NoNewPrivileges": "yes"} {
			if string(must(nil, "/usr/bin/systemctl", "show", timer+"-issuer.service", "--property="+property, "--value")) != expected {
				t.Fatal("shipped issuer unit execution or confinement failed")
			}
		}
		deadline = time.Now().Add(60 * time.Second)
		for string(fixtureSQL(t, binding, run, "SELECT count(*) FROM public.gui_certificate_generations WHERE request_id='"+requestID+"'")) != "1" {
			fixtureSQL(t, binding, run, "UPDATE public.gui_certificate_jobs SET next_attempt_at=clock_timestamp() WHERE request_id='"+requestID+"' AND state='retry_wait'")
			result := invoke()
			if result.State == "issued" {
				break
			}
			if result.State != "waiting" || time.Now().After(deadline) {
				t.Fatal("host issuer failed its bounded genuine issuance")
			}
			// Advance only the disposable queue's retry clock, as in the recovery
			// fixture. This is not a production latency measurement.
			fixtureSQL(t, binding, run, "UPDATE public.gui_certificate_jobs SET next_attempt_at=clock_timestamp() WHERE request_id='"+requestID+"' AND state='retry_wait'")
			time.Sleep(100 * time.Millisecond)
		}
		var first protocol.CertificateDelivery
		for attempt := 0; attempt < 2; attempt++ {
			status, body = client.post("issued", issuedInput)
			var delivered protocol.CertificateDelivery
			if status != 200 || json.Unmarshal(body, &delivered) != nil || delivered.Validate() != nil || delivered.Issued == nil || delivered.Request.RequestID != requestID || delivered.Request.CSRDER != client.settings.Request.CSRDER {
				t.Fatal("authenticated exact-generation delivery failed", status)
			}
			if _, err := guicert.ValidateChain([]byte(delivered.Issued.ChainPEM), csr, host, roots, time.Now()); err != nil {
				t.Fatal("delivered chain failed independent original-key trust verification")
			}
			if attempt > 0 && *first.Issued != *delivered.Issued {
				t.Fatal("delivery retry changed issued public generation")
			}
			first = delivered
		}
		if invoke().State != "idle" {
			t.Fatal("host issued work was not idempotent")
		}
		confirm := func(delivered protocol.CertificateDelivery) protocol.CertificateAppliedRequest {
			t.Helper()
			report := protocol.CertificateAppliedRequest{CertificateIssuedRequest: issuedInput, GenerationID: delivered.Issued.ID,
				Generation: delivered.Issued.Generation, LeafFingerprint: delivered.Issued.LeafFingerprint}
			// Deliberately discard the first successful response body. This tests
			// reporting recovery; it does not claim an interrupted TCP connection.
			if status, _ := client.post("applied", report); status != 200 {
				t.Fatal("initial application report failed", status)
			}
			status, body := client.post("applied", report)
			var reply protocol.CertificateAppliedResponse
			if status != 200 || json.Unmarshal(body, &reply) != nil || reply.Validate() != nil || reply.CertificateAppliedRequest != report {
				t.Fatal("application retry correlation failed", status)
			}
			stamp := fixtureSQL(t, binding, run, "SELECT to_char(accepted_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM public.gui_certificate_applications WHERE generation_id='"+report.GenerationID+"'")
			if string(stamp) != reply.AcceptedAt {
				t.Fatal("application retry lost original acceptance timestamp")
			}
			return report
		}
		firstReport := confirm(first)
		lastReport := firstReport
		if renewal {
			// Age only the labelled disposable generation's schedule. Keep the
			// genuine CA chain/key/expiry unchanged and restore immutability in
			// the same transaction; do not change any host or CA clock.
			fixtureSQL(t, binding, run, "BEGIN;ALTER TABLE public.gui_certificate_generations DISABLE TRIGGER gui_certificate_generation_immutable;UPDATE public.gui_certificate_generations SET issued_at=clock_timestamp()-interval '2 days',renew_after=clock_timestamp()-interval '1 day' WHERE id='"+first.Issued.ID+"';ALTER TABLE public.gui_certificate_generations ENABLE TRIGGER gui_certificate_generation_immutable;COMMIT")
			deadline = time.Now().Add(60 * time.Second)
			for string(fixtureSQL(t, binding, run, "SELECT count(*) FROM public.gui_certificate_generations WHERE request_id='"+requestID+"'")) != "2" {
				fixtureSQL(t, binding, run, "UPDATE public.gui_certificate_jobs SET next_attempt_at=clock_timestamp() WHERE request_id='"+requestID+"' AND state='retry_wait'")
				result := invoke()
				if result.State == "issued" {
					break
				}
				if result.State != "waiting" || time.Now().After(deadline) {
					t.Fatal("renewal did not finish its bounded genuine order")
				}
				time.Sleep(100 * time.Millisecond)
			}
			status, body = client.post("issued", issuedInput)
			var second protocol.CertificateDelivery
			if status != 200 || json.Unmarshal(body, &second) != nil || second.Validate() != nil || second.Issued == nil || second.Issued.Generation != 2 || second.Issued.ID == first.Issued.ID || second.Issued.LeafFingerprint == first.Issued.LeafFingerprint || second.Request.CSRDER != first.Request.CSRDER {
				t.Fatal("renewal did not deliver new original-key generation", status)
			}
			if _, err := guicert.ValidateChain([]byte(second.Issued.ChainPEM), csr, host, roots, time.Now()); err != nil {
				t.Fatal("renewal independent trust verification", err)
			}
			lastReport = confirm(second)
			if status, _ := client.post("applied", firstReport); status != 401 {
				t.Fatal("older application report accepted after generation two", status)
			}
			if invoke().State != "idle" {
				t.Fatal("renewal/application retries created more CA work")
			}
			counts := fixtureSQL(t, binding, run, "SELECT (SELECT count(*) FROM public.gui_certificate_requests WHERE device_id='"+client.settings.DeviceID+"'),(SELECT count(*) FROM public.gui_certificate_jobs WHERE request_id='"+requestID+"'),(SELECT count(*) FROM public.gui_certificate_generations WHERE request_id='"+requestID+"'),(SELECT count(*) FROM public.gui_certificate_applications WHERE device_id='"+client.settings.DeviceID+"'),(SELECT count(*) FROM public.audit_log WHERE target_device_id='"+client.settings.DeviceID+"' AND action='device.certificate_applied'),(SELECT count(*) FROM public.audit_log WHERE target_device_id='"+client.settings.DeviceID+"' AND action='device.certificate_renewal_queued')")
			if string(counts) != "1|2|2|2|2|1" {
				t.Fatal("renewal/reporting duplicated durable work or audits")
			}
			t.Log("Genuine host renewal passed original CSR/key, two distinct issued leaves, compiled authenticated generation delivery, discarded application response recovery, monotonic reports and exact durable job/generation/audit counts; schedule metadata was aged, no native installation")
		}
		order := fixtureSQL(t, binding, run, "SELECT checkpoint#>>'{order,finalize_url}' FROM public.gui_certificate_progress WHERE job_id=(SELECT id FROM public.gui_certificate_jobs WHERE request_id='"+requestID+"' ORDER BY generation DESC LIMIT 1)")
		if !strings.HasPrefix(string(order), files.DirectoryURL[:strings.LastIndex(files.DirectoryURL, "/")]+"/") {
			t.Fatal("host fixture order escaped configured CA")
		}
		if status, _ := client.post("unenroll", client.settings.Identity); status != 200 {
			t.Fatal("fresh client removal failed", status)
		}
		if status, _ := client.post("issued", issuedInput); status != 401 {
			t.Fatal("removed client received retained issued material", status)
		}
		if status, _ := client.post("applied", lastReport); status != 401 {
			t.Fatal("removed client acknowledged retained material", status)
		}
		if !renewal && !provisionAccount {
			testProtectedRelayTrustCommands(t, binary, directory, project, override, backup, command)
		}
		t.Log("Protected host command passed genuine Compose database discovery, independent backup/account/trust/cleanup gates, stopped-timer refusal, exact CSR issuance and idle retry; actual device HTTP admission, no appliance application")
		t.Log("Fresh compiled device enrollment, original CSR admission/initial queue, genuine CA issuance and authenticated original-key delivery passed with idempotent generation reads and removed-client denial; only initial admin/token authority was seeded")
		return guiacme.Order{Host: host, FinalizeURL: string(order)}
	})
}

func testProtectedRelayTrustCommands(t *testing.T, binary, directory, project, override, backup string, command func([]byte, string, ...string) ([]byte, error)) {
	t.Helper()
	args := func(action string, extra ...string) []string {
		return append([]string{"certificates", "relay-trust", action, "--directory", directory, "--project-name", project, "--compose-file", override}, extra...)
	}
	invoke := func(action string, extra ...string) setup.RelayTrustResult {
		t.Helper()
		raw, err := command(nil, binary, args(action, extra...)...)
		if err != nil {
			t.Fatal("protected public trust command failed")
		}
		var value setup.RelayTrustResult
		if json.Unmarshal(raw, &value) != nil || bytes.Contains(raw, []byte("BEGIN")) {
			t.Fatal("trust output was not bounded public metadata")
		}
		return value
	}
	refuse := func(action string, extra ...string) {
		t.Helper()
		raw, err := command(nil, binary, args(action, extra...)...)
		if err == nil || len(raw) != 0 {
			t.Fatal("unsafe trust operation accepted or exposed output")
		}
	}
	initial := invoke("current")
	if initial.State != "pending" || initial.ID != "" {
		t.Fatal("fresh public trust unexpectedly initialized")
	}
	oldFile := filepath.Join(directory, "secrets/issuer/ca.pem")
	old, err := os.ReadFile(oldFile)
	if err != nil {
		t.Fatal("fixture public authority unavailable")
	}
	first := invoke("publish", "--bundle-file", oldFile, "--initialize")
	if first.State != "current" || first.Number != 1 || len(first.Roots) != 1 || first.PublishedAt == "" {
		t.Fatal("initial public trust receipt")
	}
	retry := invoke("publish", "--bundle-file", oldFile, "--initialize")
	if retry.ID != first.ID || retry.PublishedAt != first.PublishedAt {
		t.Fatal("initial retry changed immutable identity")
	}
	next, err := relaycert.Create("console.example.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(filepath.Dir(directory), "public-overlap.pem")
	if os.WriteFile(bundle, append(append([]byte{}, old...), next.CA...), 0600) != nil {
		t.Fatal("overlap public fixture")
	}
	second := invoke("publish", "--bundle-file", bundle, "--expected-generation", first.ID)
	if second.Number != 2 || len(second.Roots) != 2 || second.ID == first.ID {
		t.Fatal("overlap CAS publication")
	}
	retry = invoke("publish", "--bundle-file", bundle, "--expected-generation", first.ID)
	if retry.ID != second.ID || retry.PublishedAt != second.PublishedAt {
		t.Fatal("exact overlap retry changed identity")
	}
	refuse("publish", "--bundle-file", oldFile, "--expected-generation", first.ID)
	newFile := filepath.Join(filepath.Dir(directory), "public-new.pem")
	if os.WriteFile(newFile, next.CA, 0600) != nil {
		t.Fatal("new public fixture")
	}
	refuse("publish", "--bundle-file", newFile, "--expected-generation", second.ID)
	alias := bundle + ".link"
	if os.Link(bundle, alias) != nil {
		t.Fatal("hardlink refusal fixture")
	}
	refuse("publish", "--bundle-file", bundle, "--expected-generation", second.ID)
	if os.Remove(alias) != nil {
		t.Fatal("owned alias cleanup")
	}
	if os.Symlink(bundle, alias) != nil {
		t.Fatal("symlink refusal fixture")
	}
	refuse("publish", "--bundle-file", alias, "--expected-generation", second.ID)
	if os.Remove(alias) != nil {
		t.Fatal("owned symlink cleanup")
	}
	if os.Rename(backup, backup+".unavailable") != nil {
		t.Fatal("backup refusal fixture")
	}
	_, operationErr := command(nil, binary, args("current")...)
	restoreErr := os.Rename(backup+".unavailable", backup)
	if operationErr == nil || restoreErr != nil {
		t.Fatal("missing backup admitted or original backup not restored")
	}
	current := invoke("current")
	if current.ID != second.ID || current.PublishedAt != second.PublishedAt || setup.CheckFiles(directory) != nil {
		t.Fatal("refused publication changed current trust or authority/runtime")
	}
	t.Log("Protected relay trust commands passed pending read, explicit initialization, exact retry, overlap CAS, stale/unsafe refusal and unchanged authority/runtime")
}
