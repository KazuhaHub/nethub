package setup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fixtureConfig(t *testing.T) Config {
	t.Helper()
	source, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	return Config{ConsoleHost: "console.example.com", DeviceDomain: "router.example.com", SourceDirectory: source, NetworkSubnet: "172.30.87.0/24"}
}

func TestGenerateBackupAndNonOverwrite(t *testing.T) {
	parent := t.TempDir()
	bundle, err := Generate(filepath.Join(parent, "deployment"), fixtureConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := Load(bundle)
	if err != nil || manifest.Version != 2 || manifest.ConfirmedAt != nil || len(manifest.Files) != 17 {
		t.Fatal("unexpected generated state")
	}
	if err = verifyFiles(bundle, manifest.Files); err != nil {
		t.Fatal(err)
	}
	unique := map[string]bool{}
	for _, file := range manifest.Files {
		if len(file.Path) > len("secrets/postgres/") && file.Path[:len("secrets/postgres/")] == "secrets/postgres/" && file.UID != 70 {
			t.Fatal("PostgreSQL secret owner does not match Alpine image")
		}
		unique[file.SHA256] = true
	}
	if len(unique) != 10 {
		t.Fatalf("logical secret count=%d", len(unique))
	}
	override, err := composeOverride(manifest.Config)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Services map[string]struct {
			Networks map[string]map[string]string `json:"networks"`
		} `json:"services"`
	}
	if err = json.Unmarshal(override, &config); err != nil {
		t.Fatal(err)
	}
	if config.Services["nethub-web"].Networks["edge"]["ipv4_address"] == config.Services["caddy"].Networks["edge"]["ipv4_address"] {
		t.Fatal("web and trusted proxy addresses collide")
	}
	web, _ := os.ReadDir(filepath.Join(bundle, "secrets/web"))
	if len(web) != 2 {
		t.Fatal("web received unrelated secret files")
	}
	if _, err = Generate(bundle, fixtureConfig(t)); err == nil {
		t.Fatal("existing deployment overwritten")
	}
	if _, err = Backup(bundle, filepath.Join(bundle, "backup")); err == nil {
		t.Fatal("nested backup accepted")
	}
	backup, err := Backup(bundle, filepath.Join(parent, "backup"))
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyBackup(bundle, backup); err != nil {
		t.Fatal(err)
	}
	if err = VerifyBackup(bundle, bundle); err == nil {
		t.Fatal("self backup accepted")
	}
	if err = Confirm(bundle, backup, "yes"); err == nil {
		t.Fatal("missing exact acknowledgement accepted")
	}
	if err = CheckFiles(bundle); err == nil {
		t.Fatal("unconfirmed bundle reported ready")
	}
	path := filepath.Join(backup, filepath.FromSlash(manifest.Files[0].Path))
	if err = os.WriteFile(path, bytes.Repeat([]byte{'x'}, 65), 0600); err != nil {
		t.Fatal(err)
	}
	if err = VerifyBackup(bundle, backup); err == nil {
		t.Fatal("corrupted backup accepted")
	}
	if runtime.GOOS != "windows" {
		path = filepath.Join(bundle, filepath.FromSlash(manifest.Files[0].Path))
		if err = os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if err = verifyFiles(bundle, manifest.Files); err == nil {
			t.Fatal("publicly readable secret accepted")
		}
	}
}

func TestConfigAndManifestBoundaries(t *testing.T) {
	valid := fixtureConfig(t)
	for name, change := range map[string]func(*Config){
		"same domain":            func(c *Config) { c.ConsoleHost = c.DeviceDomain },
		"console under wildcard": func(c *Config) { c.ConsoleHost = "console." + c.DeviceDomain },
		"injection":              func(c *Config) { c.ConsoleHost = "console.example.com\nreverse_proxy evil" },
		"wildcard":               func(c *Config) { c.DeviceDomain = "*.example.com" },
		"IP":                     func(c *Config) { c.DeviceDomain = "192.0.2.1" },
		"public subnet":          func(c *Config) { c.NetworkSubnet = "192.0.2.0/24" },
		"large subnet":           func(c *Config) { c.NetworkSubnet = "172.30.0.0/16" },
		"unaligned subnet":       func(c *Config) { c.NetworkSubnet = "172.30.87.2/24" },
		"missing source":         func(c *Config) { c.SourceDirectory = "relative" },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			change(&c)
			if err := Validate(c); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	bundle, err := Generate(filepath.Join(t.TempDir(), "deployment"), valid)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := Load(bundle)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Version = 1
	legacy, _ := json.Marshal(manifest)
	if err = os.WriteFile(filepath.Join(bundle, "setup.json"), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(bundle); err == nil {
		t.Fatal("legacy UID scheme accepted without explicit migration")
	}
	manifest.Version = 2
	manifest.Files[0].Path = "../outside"
	data, _ := json.Marshal(manifest)
	if err = os.WriteFile(filepath.Join(bundle, "setup.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(bundle); err == nil {
		t.Fatal("manifest path escape accepted")
	}
}

func TestEmbeddedTemplatesMatchReviewedDeploymentFiles(t *testing.T) {
	for name, path := range map[string]string{"docker-compose.yml": "../../../deploy/docker-compose.yml", "Caddyfile": "../../../deploy/Caddyfile", "00-nethub-roles.sh": "../../../deploy/postgres/00-nethub-roles.sh"} {
		expected, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := templates.ReadFile("templates/" + name)
		if err != nil {
			t.Fatal(err)
		}
		normalize := func(data []byte) []byte { return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")) }
		if !bytes.Equal(normalize(expected), normalize(actual)) {
			t.Fatalf("embedded %s differs from reviewed deployment template", name)
		}
	}
}
