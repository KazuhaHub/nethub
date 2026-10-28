package guiissuer_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relayprobe"
	"github.com/KazuhaHub/nethub/server/internal/setup"
)

func TestNativeRelayAuthorityService(t *testing.T) {
	directory := os.Getenv("NETHUB_TEST_AUTHORITY_DIRECTORY")
	if directory == "" {
		t.Skip("requires the isolated running Compose deployment")
	}
	if os.Geteuid() != 0 {
		t.Fatal("service acceptance requires its protected root fixture")
	}
	project := os.Getenv("NETHUB_TEST_GUI_SQL_PROJECT")
	override := os.Getenv("NETHUB_TEST_AUTHORITY_COMPOSE")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	id := func(name string) string {
		t.Helper()
		command := exec.CommandContext(ctx, "/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "compose", "--project-name", project, "--file", filepath.Join(directory, "docker-compose.yml"), "--file", filepath.Join(directory, "docker-compose.override.yml"), "--file", override, "ps", "--all", "--quiet", name)
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
		raw, err := command.Output()
		value := strings.TrimSpace(string(raw))
		if err != nil || len(value) != 64 {
			t.Fatal("fixture container identity unavailable")
		}
		return value
	}
	before := map[string]string{}
	for _, name := range []string{"postgres", "nethub-web", "caddy", "nethub-authz", "frps", "backup"} {
		before[name] = id(name)
	}
	checkContainers := func(want bool) {
		t.Helper()
		if (setup.CheckRuntimeContainers(ctx, directory, project, override) == nil) != want {
			t.Fatal("actual runtime container doctor returned an unexpected result")
		}
		binary := os.Getenv("NETHUB_TEST_AUTHORITY_CLI")
		if binary == "" {
			t.Fatal("compiled container doctor is required")
		}
		command := exec.CommandContext(ctx, binary, "doctor", "--runtime-containers", "--directory", directory, "--project", project, "--compose-file", override)
		output, err := command.CombinedOutput()
		if (err == nil) != want {
			t.Fatal("compiled runtime container doctor returned an unexpected result")
		}
		if want && !strings.Contains(string(output), "inspection did not modify services") {
			t.Fatal("container doctor omitted its inspection scope")
		}
		if !want && !strings.Contains(string(output), "restore reviewed service users") {
			t.Fatal("container doctor omitted remediation")
		}
	}
	checkContainers(true)
	for _, serviceName := range []string{"web", "backup"} {
		extra := filepath.Join(directory, "secrets", serviceName, "doctor-unexpected-fixture")
		file, err := os.OpenFile(extra, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal("could not create owned nonsecret container fixture")
		}
		t.Cleanup(func() {
			if err := os.Remove(extra); err != nil && !os.IsNotExist(err) {
				t.Error("owned container readiness fixture cleanup failed")
			}
		})
		if _, err := file.WriteString("unexpected nonsecret readiness fixture\n"); err != nil {
			file.Close()
			t.Fatal(err)
		}
		file.Close()
		checkContainers(false)
		if err := os.Remove(extra); err != nil {
			t.Fatal("owned readiness fixture removal failed")
		}
		checkContainers(true)
	}
	for name, original := range before {
		if id(name) != original {
			t.Fatal("read-only container doctor changed a service", name)
		}
	}
	t.Log("Actual Docker and compiled container doctor verified running Web/authz/frps/backup separation, refused unexpected Web and backup secret files, recovered after owned cleanup and left all six services unchanged")
	service, err := setup.BindRelayAuthorityService(ctx, directory, project, override, "")
	if err != nil {
		t.Fatal("running protected authority service binding", err)
	}
	fingerprint := service.Fingerprint()
	if _, err := setup.BindRelayAuthorityService(ctx, directory, project, override, strings.Repeat("0", 64)); err == nil {
		t.Fatal("unrelated recovery service fingerprint accepted")
	}
	rebound, err := setup.BindRelayAuthorityService(ctx, directory, project, override, fingerprint)
	if err != nil || rebound.Fingerprint() != fingerprint {
		t.Fatal("exact service rebind changed identity", err)
	}
	ca, err := os.ReadFile(filepath.Join(directory, "runtime/trust/relay-ca.pem"))
	if err != nil {
		t.Fatal("fixture trust")
	}
	cert, err := os.ReadFile(filepath.Join(directory, "runtime/relay/relay-cert.pem"))
	if err != nil {
		t.Fatal("fixture leaf")
	}
	block, _ := pem.Decode(cert)
	if block == nil {
		t.Fatal("fixture certificate")
	}
	digest := sha256.Sum256(block.Bytes)
	expected := hex.EncodeToString(digest[:])
	if observed, err := service.Observe(ctx, ca); err != nil || observed != expected {
		t.Fatal("original actual relay TLS verification", err)
	}
	manifest, err := setup.Load(directory)
	if err != nil {
		t.Fatal("relay doctor fixture identity unavailable")
	}
	counts := func() string {
		t.Helper()
		command := exec.CommandContext(ctx, "/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "exec", "--user", "postgres", before["postgres"], "psql", "-X", "-qAt", "--username", "postgres", "--dbname", "nethub", "--set", "ON_ERROR_STOP=1", "--command", `SELECT (SELECT count(*) FROM devices)::text||':'||(SELECT count(*) FROM device_access_grants)::text||':'||(SELECT count(*) FROM audit_log)::text`)
		output, err := command.Output()
		if err != nil {
			t.Fatal("relay doctor fixture state count unavailable")
		}
		return string(output)
	}
	countsBefore := counts()
	if version, err := relayprobe.Check(ctx, "127.0.0.1:7000", manifest.Config.ConsoleHost, ca); err != nil || version != relayprobe.ProtocolVersion {
		t.Fatal("actual relay rejection/version probe failed", err)
	}
	probeCLI := exec.CommandContext(ctx, os.Getenv("NETHUB_TEST_AUTHORITY_CLI"), "doctor", "--relay-hook", "--directory", directory, "--project", project, "--compose-file", override)
	if output, err := probeCLI.CombinedOutput(); err != nil || !strings.Contains(string(output), "Relay TLS and Login hook rejection path passed") {
		t.Fatal("compiled actual relay doctor failed")
	}
	if counts() != countsBefore {
		t.Fatal("denied relay probe changed device, grant or audit counts")
	}
	t.Log("Actual pinned frps/authz and compiled doctor passed verified-TLS invalid-claim rejection and running protocol version with unchanged device/grant/audit counts and no submitted credentials or proxy")
	if service.Reload(ctx, []byte("unrelated public trust")) == nil {
		t.Fatal("unrelated trust initiated service reload")
	}
	for name, original := range before {
		if id(name) != original {
			t.Fatal("refused reload changed a service", name)
		}
	}
	stopAuthz := exec.CommandContext(ctx, "/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "compose", "--project-name", project, "--file", filepath.Join(directory, "docker-compose.yml"), "--file", filepath.Join(directory, "docker-compose.override.yml"), "--file", override, "stop", "nethub-authz")
	stopAuthz.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	if _, err := stopAuthz.CombinedOutput(); err != nil {
		t.Fatal("owned hook outage fixture failed")
	}
	if _, err := relayprobe.Check(ctx, "127.0.0.1:7000", manifest.Config.ConsoleHost, ca); err == nil {
		t.Fatal("unavailable actual authz hook passed relay doctor")
	}
	t.Log("Actual relay doctor refused the existing TLS relay when its authz Login hook was unavailable; the original bound recovery test restores the owned services")
	// Remove only this disposable project's already-bound relay, modelling an
	// interruption between Compose's remove/create phases. Initial binding must
	// refuse it; the exact protected recovery binding may recreate that service.
	remove := exec.CommandContext(ctx, "/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "compose", "--project-name", project, "--file", filepath.Join(directory, "docker-compose.yml"), "--file", filepath.Join(directory, "docker-compose.override.yml"), "--file", override, "rm", "--stop", "--force", "frps")
	remove.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	if remove.Run() != nil {
		t.Fatal("could not prepare exact owned missing-service fixture")
	}
	if _, err := setup.BindRelayAuthorityService(ctx, directory, project, override, ""); err == nil {
		t.Fatal("initial binding accepted absent relay")
	}
	service, err = setup.BindRelayAuthorityService(ctx, directory, project, override, fingerprint)
	if err != nil {
		t.Fatal("exact recovery binding refused interrupted recreation", err)
	}
	if service.Reload(ctx, ca) != nil {
		t.Fatal("bound authz/frps reload failed")
	}
	if observed, err := service.Observe(ctx, ca); err != nil || observed != expected {
		t.Fatal("fresh actual relay TLS after reloading both services", err)
	}
	for _, name := range []string{"postgres", "nethub-web", "caddy"} {
		if id(name) != before[name] {
			t.Fatal("reload changed unrelated service", name)
		}
	}
	for _, name := range []string{"nethub-authz", "frps"} {
		if id(name) == before[name] {
			t.Fatal("reload did not recreate selected service", name)
		}
	}
	if setup.CheckFiles(directory) != nil {
		t.Fatal("service reload changed confirmed authority files")
	}
	t.Log("Bound authority service passed actual authz/frps recreation, health, immutable configuration/rebind, wrong-trust refusal, unchanged unrelated services and independently verified served TLS; same authority, no root transition")
}
