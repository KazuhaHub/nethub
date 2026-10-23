package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratedCertificateAdmissionDomain(t *testing.T) {
	for _, mode := range []string{"bundled", "external"} {
		t.Run(mode, func(t *testing.T) {
			config := fixtureConfig(t)
			if mode == "external" {
				config.ProxyMode = mode
			}
			directory, err := Generate(filepath.Join(t.TempDir(), "deployment"), config)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(directory, "docker-compose.override.yml"))
			if err != nil {
				t.Fatal(err)
			}
			var override struct {
				Services map[string]struct {
					Command []string `json:"command"`
				} `json:"services"`
			}
			if err := json.Unmarshal(raw, &override); err != nil {
				t.Fatal(err)
			}
			for _, service := range []string{"nethub-authz", "nethub-web"} {
				arguments := override.Services[service].Command
				count := 0
				for i, argument := range arguments {
					if argument != "--device-domain" {
						continue
					}
					count++
					if i+1 == len(arguments) || arguments[i+1] != config.DeviceDomain {
						t.Fatalf("%s does not use the deployment device domain", service)
					}
				}
				if count != 1 {
					t.Fatalf("%s has %d device-domain arguments; certificate admission requires one", service, count)
				}
			}
		})
	}
}
