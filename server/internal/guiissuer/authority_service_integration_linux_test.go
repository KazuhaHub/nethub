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
	for _, name := range []string{"postgres", "nethub-web", "caddy", "nethub-authz", "frps"} {
		before[name] = id(name)
	}
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
	if service.Reload(ctx, []byte("unrelated public trust")) == nil {
		t.Fatal("unrelated trust initiated service reload")
	}
	for name, original := range before {
		if id(name) != original {
			t.Fatal("refused reload changed a service", name)
		}
	}
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
