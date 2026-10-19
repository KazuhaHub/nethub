package setup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalProxyBundle(t *testing.T) {
	config := fixtureConfig(t)
	config.ProxyMode = "external"
	config.WebPort, config.DevicePort = 28080, 28081
	directory, err := Generate(filepath.Join(t.TempDir(), "external"), config)
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(filepath.Join(directory, "docker-compose.yml"))
	if err != nil || bytes.Contains(base, []byte("  caddy:\n")) {
		t.Fatal("bundled TLS owner remains enabled")
	}
	for _, name := range []string{"nethub-web", "nethub-authz", "frps", "postgres", "migrate"} {
		if !bytes.Contains(base, []byte("  "+name+":\n")) {
			t.Fatalf("missing service %s", name)
		}
	}
	raw, err := os.ReadFile(filepath.Join(directory, "docker-compose.override.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var override struct {
		Services map[string]struct {
			Command []string `json:"command"`
			Ports   []struct {
				HostIP    string `json:"host_ip"`
				Published int    `json:"published"`
				Target    int    `json:"target"`
			} `json:"ports"`
		} `json:"services"`
	}
	if err = json.Unmarshal(raw, &override); err != nil {
		t.Fatal(err)
	}
	if _, ok := override.Services["caddy"]; ok {
		t.Fatal("override recreates bundled TLS owner")
	}
	for name, port := range map[string]int{"nethub-web": 28080, "nethub-authz": 28081} {
		s := override.Services[name]
		if len(s.Ports) != 1 || s.Ports[0].HostIP != "127.0.0.1" || s.Ports[0].Published != port {
			t.Fatal("origin published beyond loopback or wrong port")
		}
		trusted := ""
		for i, v := range s.Command {
			if v == "--trusted-proxy" {
				trusted = s.Command[i+1]
			}
		}
		if trusted != "172.30.87.1/32" {
			t.Fatal("unexpected external proxy trust")
		}
	}
	sample, err := os.ReadFile(filepath.Join(directory, "external-Caddyfile.example"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"console.example.com", "127.0.0.1:28080", "127.0.0.1:28081", "X-Forwarded-For {remote_host}", "respond @internal 404"} {
		if !strings.Contains(string(sample), value) {
			t.Fatal("external proxy sample lacks required routing/trust")
		}
	}
	manifest, err := Load(directory)
	if err != nil || !manifest.Config.externalProxy() {
		t.Fatal("external mode was not persisted")
	}
}

func TestExternalProxyValidationAndTemplateBoundary(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.ProxyMode = "unknown" },
		func(c *Config) { c.WebPort = 18080 },
		func(c *Config) { c.ProxyMode = "external"; c.WebPort = 8443 },
		func(c *Config) { c.ProxyMode = "external"; c.DevicePort = 18080 },
		func(c *Config) { c.ProxyMode = "external"; c.DevicePort = 443 },
	} {
		config := fixtureConfig(t)
		change(&config)
		if Validate(config) == nil {
			t.Fatal("invalid proxy settings accepted")
		}
	}
	for _, input := range []string{"", "\n  caddy:\nchanged", "\n  caddy:\n\n  caddy:\n\nnetworks:\n", "\n  caddy:\n    image: caddy\n  another:\n    image: example\nnetworks:\n"} {
		if _, err := externalBase([]byte(input)); err == nil {
			t.Fatal("changed template boundary accepted")
		}
	}
}
