package setup

import (
	"encoding/json"
	"net/netip"
	"strconv"
)

func edgeAddresses(config Config) (gateway, caddy, web, authz string) {
	prefix, _ := netip.ParsePrefix(config.NetworkSubnet)
	ip := prefix.Addr().Next()
	return ip.String(), ip.Next().String(), ip.Next().Next().String(), ip.Next().Next().Next().String()
}

func composeOverride(config Config) ([]byte, error) {
	gateway, caddyIP, webIP, authzIP := edgeAddresses(config)
	result := map[string]any{
		"services": map[string]any{
			"postgres":     map[string]any{"build": map[string]any{"context": config.SourceDirectory, "dockerfile": "deploy/images/postgres/Dockerfile"}},
			"migrate":      map[string]any{"build": map[string]any{"context": config.SourceDirectory, "dockerfile": "deploy/Dockerfile"}},
			"nethub-web":   map[string]any{"command": []string{"web", "--password-file", "/run/secrets/pg_nethub_web", "--secrets-key-file", "/run/secrets/secrets_key", "--sslmode", "disable", "--listen", ":8080", "--origin", "https://" + config.ConsoleHost, "--device-domain", config.DeviceDomain, "--trusted-proxy", caddyIP + "/32"}, "networks": map[string]any{"database": map[string]string{}, "edge": map[string]string{"ipv4_address": webIP}}},
			"nethub-authz": map[string]any{"command": []string{"authz", "--password-file", "/run/secrets/pg_nethub_authz", "--sslmode", "disable", "--listen", ":8081", "--origin", "https://" + config.ConsoleHost, "--device-domain", config.DeviceDomain, "--claim-key-file", "/run/secrets/claim_key", "--frp-token-file", "/run/secrets/frp_token", "--relay-ca-file", "/run/trust/relay-ca.pem", "--relay-addr", config.ConsoleHost, "--relay-server-name", config.ConsoleHost, "--trusted-proxy", caddyIP + "/32", "--hook-listen", authzIP + ":9000", "--hook-peer", gateway, "--frps-admin-origin", "http://" + gateway + ":7500", "--frps-admin-user-file", "/run/secrets/frps_admin_user", "--frps-admin-password-file", "/run/secrets/frps_admin_password"}, "networks": map[string]any{"database": map[string]string{}, "edge": map[string]string{"ipv4_address": authzIP}}},
			"frps":         map[string]any{"build": map[string]any{"context": config.SourceDirectory, "dockerfile": "deploy/images/frps/Dockerfile"}},
			"caddy":        map[string]any{"build": map[string]any{"context": config.SourceDirectory, "dockerfile": "deploy/images/caddy/Dockerfile"}, "environment": map[string]string{"NETHUB_CONSOLE_HOST": config.ConsoleHost}, "networks": map[string]any{"edge": map[string]string{"ipv4_address": caddyIP}}},
		},
		"networks": map[string]any{"edge": map[string]any{"ipam": map[string]any{"config": []map[string]string{{"subnet": config.NetworkSubnet, "gateway": gateway}}}}},
	}
	// frps uses host networking. A loopback publication refuses new callbacks
	// promptly when authz stops instead of dialing its removed bridge endpoint.
	authzService := result["services"].(map[string]any)["nethub-authz"].(map[string]any)
	authzService["ports"] = []map[string]any{{"host_ip": "127.0.0.1", "published": 9000, "target": 9000, "protocol": "tcp"}}
	if config.AnomalyActionLimit != 0 {
		authzService["command"] = append(authzService["command"].([]string), "--anomaly-action-limit", strconv.Itoa(config.AnomalyActionLimit))
	}
	if config.externalProxy() {
		services := result["services"].(map[string]any)
		delete(services, "caddy")
		webPort, devicePort := config.originPorts()
		for name, port := range map[string]uint16{"nethub-web": webPort, "nethub-authz": devicePort} {
			service := services[name].(map[string]any)
			args := service["command"].([]string)
			for i := range args {
				if args[i] == "--trusted-proxy" {
					args[i+1] = gateway + "/32"
				}
			}
			target := 8080
			if name == "nethub-authz" {
				target = 8081
			}
			ports, _ := service["ports"].([]map[string]any)
			service["ports"] = append(ports, map[string]any{"host_ip": "127.0.0.1", "published": port, "target": target, "protocol": "tcp"})
		}
	}
	return json.MarshalIndent(result, "", "  ")
}
