package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAnomalyLimitConfigurationAndLegacyOmission(t *testing.T) {
	for _, mode := range []string{"bundled", "external"} {
		for _, limit := range []int{0, 1, 7, 1024} {
			config := fixtureConfig(t)
			config.ProxyMode = mode
			config.AnomalyActionLimit = limit
			if err := Validate(config); err != nil {
				t.Fatal(err)
			}
			raw, err := composeOverride(config)
			if err != nil {
				t.Fatal(err)
			}
			var output struct {
				Services map[string]struct{ Command []string }
			}
			if json.Unmarshal(raw, &output) != nil {
				t.Fatal("invalid generated override")
			}
			count := 0
			args := output.Services["nethub-authz"].Command
			for index, arg := range args {
				if arg == "--anomaly-action-limit" {
					count++
					if index+1 >= len(args) || args[index+1] != strconv.Itoa(limit) {
						t.Fatal("anomaly allowance changed during generation")
					}
				}
			}
			if limit == 0 && count != 0 || limit != 0 && count != 1 {
				t.Fatal("legacy command changed or explicit limit duplicated")
			}
		}
	}
	for _, limit := range []int{-1, 1025} {
		config := fixtureConfig(t)
		config.AnomalyActionLimit = limit
		if Validate(config) == nil {
			t.Fatal("invalid managed allowance accepted")
		}
	}
}

func TestGeneratedHookLoopbackPublication(t *testing.T) {
	for _, mode := range []string{"bundled", "external"} {
		t.Run(mode, func(t *testing.T) {
			config := fixtureConfig(t)
			config.ProxyMode = mode
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
					Ports   []struct {
						HostIP    string `json:"host_ip"`
						Published int    `json:"published"`
						Target    int    `json:"target"`
						Protocol  string `json:"protocol"`
					} `json:"ports"`
				} `json:"services"`
			}
			if err := json.Unmarshal(raw, &override); err != nil {
				t.Fatal(err)
			}
			service := override.Services["nethub-authz"]
			count := 0
			for _, port := range service.Ports {
				if port.Published == 9000 || port.Target == 9000 {
					count++
					if port.HostIP != "127.0.0.1" || port.Published != 9000 || port.Target != 9000 || port.Protocol != "tcp" {
						t.Fatal("hook publication must use the exact host loopback port")
					}
				}
			}
			if count != 1 {
				t.Fatal("missing or duplicated hook publication")
			}
			gateway, _, _, authz := edgeAddresses(config)
			for flag, want := range map[string]string{"--hook-listen": authz + ":9000", "--hook-peer": gateway} {
				count := 0
				for i, argument := range service.Command {
					if argument == flag {
						count++
						if i+1 >= len(service.Command) || service.Command[i+1] != want {
							t.Fatalf("changed private hook boundary %s", flag)
						}
					}
				}
				if count != 1 {
					t.Fatalf("missing or duplicated %s", flag)
				}
			}
			relay, err := os.ReadFile(filepath.Join(directory, "secrets/frps/frps.toml"))
			if err != nil || !strings.Contains(string(relay), "addr = \"127.0.0.1:9000\"") || strings.Contains(string(relay), authz+":9000") {
				t.Fatal("host-network frps must use the loopback publication")
			}
		})
	}
}

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
