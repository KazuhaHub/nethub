//go:build linux

package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/http01"
)

func http01InitializationFixture(t *testing.T) (string, string, http01.FileConfig) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires the root deployment acceptance job")
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	for _, name := range []string{"deploy/Dockerfile", "deploy/images/caddy/Dockerfile", "deploy/images/postgres/Dockerfile", "deploy/images/frps/Dockerfile"} {
		path := filepath.Join(source, name)
		if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, []byte("FROM scratch\n"), 0600) != nil {
			t.Fatal("fixture source creation failed")
		}
	}
	directory, err := Generate(filepath.Join(root, "deployment"), Config{ConsoleHost: "console.example.test", DeviceDomain: "devices.example.test", SourceDirectory: source, NetworkSubnet: "172.30.87.0/24"})
	if err != nil {
		t.Fatal("fixture deployment generation failed", err)
	}
	backup, err := Backup(directory, filepath.Join(root, "backup"))
	if err != nil || Confirm(directory, backup, BackupPhrase) != nil {
		t.Fatal("fixture independent backup failed")
	}
	return directory, filepath.Join(root, "http01.json"), http01.FileConfig{Version: 1, PublicDirectory: filepath.Join(root, "public"), StateDirectory: filepath.Join(root, "private"), DeviceDomain: "devices.example.test", ExcludedHosts: []string{"console.example.test"}}
}

func writeHTTP01InitializationPolicy(t *testing.T, path string, policy http01.FileConfig) {
	t.Helper()
	data, err := json.Marshal(policy)
	if err != nil || os.WriteFile(path, data, 0600) != nil {
		t.Fatal("fixture policy creation failed")
	}
}

func TestHTTP01InitializationCreatesAndPreservesNamespace(t *testing.T) {
	directory, path, policy := http01InitializationFixture(t)
	writeHTTP01InitializationPolicy(t, path, policy)
	if InitializeHTTP01(context.Background(), directory, path) != nil {
		t.Fatal("explicit initialization failed")
	}
	files := []string{filepath.Join(policy.PublicDirectory, ".publisher.json"), filepath.Join(policy.PublicDirectory, ".publisher-lease"), filepath.Join(policy.StateDirectory, "namespace.json")}
	before := map[string][]byte{}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal("initialized identity missing")
		}
		before[name] = data
	}
	if InitializeHTTP01(context.Background(), directory, path) != nil {
		t.Fatal("exact retry failed")
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(data, before[name]) {
			t.Fatal("exact retry changed namespace identity")
		}
	}
	if _, err := http01.OpenExistingFile(path); err != nil {
		t.Fatal("cleanup cannot open the initialized namespace")
	}
	marker := filepath.Join(policy.StateDirectory, "namespace.json")
	if os.Remove(marker) != nil || InitializeHTTP01(context.Background(), directory, path) == nil {
		t.Fatal("lost private identity was adopted")
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("lost private identity was recreated")
	}
}

func TestHTTP01InitializationRefusesUnsafePolicyBeforeMutation(t *testing.T) {
	for _, kind := range []string{"domain", "console", "overlap", "writable-parent", "cancelled", "unconfirmed", "backup-missing", "partial"} {
		t.Run(kind, func(t *testing.T) {
			directory, path, policy := http01InitializationFixture(t)
			ctx := context.Background()
			switch kind {
			case "domain":
				policy.DeviceDomain = "unrelated.example.test"
			case "console":
				policy.ExcludedHosts = []string{}
			case "overlap":
				policy.PublicDirectory = filepath.Join(directory, "public")
			case "writable-parent":
				parent := filepath.Join(filepath.Dir(path), "unsafe")
				if os.Mkdir(parent, 0777) != nil || os.Chmod(parent, 0777) != nil {
					t.Fatal("unsafe parent fixture failed")
				}
				policy.PublicDirectory = filepath.Join(parent, "public")
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unconfirmed":
				manifest, err := Load(directory)
				if err != nil {
					t.Fatal("fixture manifest read failed")
				}
				manifest.ConfirmedAt = nil
				data, err := json.Marshal(manifest)
				if err != nil || os.WriteFile(filepath.Join(directory, "setup.json"), data, 0600) != nil {
					t.Fatal("fixture confirmation removal failed")
				}
			case "backup-missing":
				// Loss of the independent copy must prevent namespace creation.
				backup := filepath.Join(filepath.Dir(path), "backup")
				if os.Rename(backup, backup+"-unavailable") != nil {
					t.Fatal("fixture backup removal failed")
				}
			case "partial":
				if os.Mkdir(policy.PublicDirectory, 0755) != nil {
					t.Fatal("partial namespace fixture failed")
				}
			}
			writeHTTP01InitializationPolicy(t, path, policy)
			if InitializeHTTP01(ctx, directory, path) == nil {
				t.Fatal("unsafe initialization accepted")
			}
			if kind != "partial" {
				if _, err := os.Lstat(policy.PublicDirectory); !os.IsNotExist(err) {
					t.Fatal("refused initialization created public state")
				}
			}
			if _, err := os.Lstat(policy.StateDirectory); !os.IsNotExist(err) {
				t.Fatal("refused initialization created private state")
			}
		})
	}
}

func TestHTTP01InitializationCompiledCommand(t *testing.T) {
	directory, path, policy := http01InitializationFixture(t)
	binary := os.Getenv("NETHUB_TEST_AUTHORITY_CLI")
	if binary == "" {
		if os.Getenv("NETHUB_TEST_HTTP01_CLI_REQUIRED") == "1" {
			t.Fatal("deployment acceptance requires the compiled HTTP-01 initializer")
		}
		t.Skip("requires the compiled deployment CLI")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("compiled CLI identity missing")
	}
	writeHTTP01InitializationPolicy(t, path, policy)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "certificates", "initialize-http01", "--directory", directory, "--config-file", path)
	var out, diagnostic bytes.Buffer
	command.Stdout, command.Stderr = &out, &diagnostic
	if command.Run() != nil || out.String() != "{\"state\":\"initialized\"}\n" || diagnostic.Len() != 0 {
		t.Fatal("compiled namespace initialization failed")
	}
	if _, err := http01.OpenExistingFile(path); err != nil {
		t.Fatal("compiled CLI did not initialize the real namespace")
	}
	t.Log("Compiled HTTP-01 initialization passed deployment-bound creation and cleanup readiness")
}
