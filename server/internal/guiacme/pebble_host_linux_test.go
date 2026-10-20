package guiacme_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/KazuhaHub/nethub/server/internal/setup"
)

// This opt-in fixture starts only nonce-owned, portless Compose PostgreSQL and
// private CA/proxy resources. Its outer deployment harness arms an independent
// exact-resource cleanup guard before entering this test.
func TestPebbleProtectedHostIssuer(t *testing.T) {
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
	guiacme.RunPebbleHostFixture(t, func(files guiacme.PebbleHostFiles, account *guiacme.AccountStore, publisher *http01.Publisher, roots *x509.CertPool, csr []byte, public string) guiacme.Order {
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
		invoke := func() setup.GUIIssuerResult {
			t.Helper()
			data := must(nil, binary, args...)
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
		if _, err := command(nil, binary, args...); err == nil {
			t.Fatal("host issuer accepted an uninitialized account")
		}
		if _, err := os.Lstat(missingAccount.AccountDirectory); !os.IsNotExist(err) {
			t.Fatal("ordinary host work initialized or replaced account state")
		}
		write(issuerFile, policyBytes)
		must(nil, "/usr/bin/systemctl", "stop", timer+".timer")
		if _, err := command(nil, binary, args...); err == nil {
			t.Fatal("issuer accepted a stopped independent cleanup timer")
		}
		must(nil, "/usr/bin/systemctl", "start", timer+".timer")
		request, err := guicert.ValidateBoundCSR(csr, "abcdefgh.devices.example.test", public)
		if err != nil {
			t.Fatal(err)
		}
		const requestID = "b4444444-4444-4444-4444-444444444444"
		fixtureSQL(t, binding, run, fmt.Sprintf(`BEGIN;
INSERT INTO public.tenants(id,name) VALUES('b1111111-1111-1111-1111-111111111111','Isolated host fixture');
INSERT INTO public.users(id,tenant_id,email,role) VALUES('b2222222-2222-2222-2222-222222222222','b1111111-1111-1111-1111-111111111111','host@example.test','member');
INSERT INTO public.devices(id,tenant_id,owner_user_id,platform,device_secret_hash,subdomain,agent_protocol_version,gui_public_key) VALUES('b3333333-3333-3333-3333-333333333333','b1111111-1111-1111-1111-111111111111','b2222222-2222-2222-2222-222222222222','opnsense','fixture-not-a-credential','abcdefgh','1.2.0','%s');
INSERT INTO public.gui_certificate_requests(id,tenant_id,device_id,assigned_host,gui_public_key,csr_der) VALUES('%s','b1111111-1111-1111-1111-111111111111','b3333333-3333-3333-3333-333333333333','abcdefgh.devices.example.test','%s',decode('%s','hex'));COMMIT`, public, requestID, public, hex.EncodeToString(request.DER)))
		if _, err := run(context.Background(), []byte("SET SESSION AUTHORIZATION nethub_issuer;SELECT public.enqueue_gui_certificate_request('"+requestID+"');")); err != nil {
			t.Fatal("host fixture initial queue")
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
			"/var/lib/nethub-gui-acme":    files.AccountDirectory,
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
		chainHex := fixtureSQL(t, binding, run, "SELECT encode(chain_pem,'hex') FROM public.gui_certificate_generations WHERE request_id='"+requestID+"'")
		chain, err := hex.DecodeString(string(chainHex))
		if err != nil {
			t.Fatal("host issued material encoding")
		}
		if _, err := guicert.ValidateChain(chain, csr, "abcdefgh.devices.example.test", roots, time.Now()); err != nil || invoke().State != "idle" {
			t.Fatal("host chain binding or post-issuance idempotence")
		}
		order := fixtureSQL(t, binding, run, "SELECT checkpoint#>>'{order,finalize_url}' FROM public.gui_certificate_progress WHERE job_id=(SELECT id FROM public.gui_certificate_jobs WHERE request_id='"+requestID+"')")
		if !strings.HasPrefix(string(order), files.DirectoryURL[:strings.LastIndex(files.DirectoryURL, "/")]+"/") {
			t.Fatal("host fixture order escaped configured CA")
		}
		t.Log("Protected host command passed genuine Compose database discovery, independent backup/account/trust/cleanup gates, stopped-timer refusal, exact CSR issuance and idle retry; seeded public metadata, no appliance application")
		return guiacme.Order{FinalizeURL: string(order)}
	})
}
