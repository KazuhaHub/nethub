package setup

import (
	"encoding/json"
	"net/netip"
)

func composeOverride(config Config) ([]byte, error) {
	prefix, _ := netip.ParsePrefix(config.NetworkSubnet)
	caddyIP := prefix.Addr().Next().Next().String()
	webIP := prefix.Addr().Next().Next().Next().String()
	return json.MarshalIndent(map[string]any{
		"services": map[string]any{
			"migrate":    map[string]any{"build": map[string]any{"context": config.SourceDirectory, "dockerfile": "deploy/Dockerfile"}},
			"nethub-web": map[string]any{"command": []string{"web", "--password-file", "/run/secrets/pg_nethub_web", "--sslmode", "disable", "--listen", ":8080", "--origin", "https://" + config.ConsoleHost, "--device-domain", config.DeviceDomain, "--trusted-proxy", caddyIP + "/32"}, "networks": map[string]any{"database": map[string]string{}, "edge": map[string]string{"ipv4_address": webIP}}},
			"caddy":      map[string]any{"environment": map[string]string{"NETHUB_CONSOLE_HOST": config.ConsoleHost}, "networks": map[string]any{"edge": map[string]string{"ipv4_address": caddyIP}}},
		},
		"networks": map[string]any{"edge": map[string]any{"ipam": map[string]any{"config": []map[string]string{{"subnet": config.NetworkSubnet}}}}},
	}, "", "  ")
}
