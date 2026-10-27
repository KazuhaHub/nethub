package setup

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestReadinessWebContainerRejectsExcessAuthority(t *testing.T) {
	for _, external := range []bool{false, true} {
		s, c := authorityServiceFixture(t, "nethub-authz", external)
		c.Config.Cmd = expectedAuthorityCommand(s.binding.Config, "nethub-web")
		c.Config.Labels["com.docker.compose.service"] = "nethub-web"
		_, _, ip, _ := edgeAddresses(s.binding.Config)
		c.NetworkSettings.Networks["fixture_edge"] = authorityNetwork{IPAddress: ip}
		c.Mounts = c.Mounts[:1]
		c.Mounts[0].Type, c.Mounts[0].Source, c.Mounts[0].Destination, c.Mounts[0].RW = "bind", filepath.Join(s.binding.Directory, "secrets/web"), "/run/secrets", false
		c.HostConfig.PortBindings = nil
		if external {
			c.HostConfig.PortBindings = map[string][]struct{ HostIP, HostPort string }{"8080/tcp": {{HostIP: "127.0.0.1", HostPort: "18080"}}}
		}
		image := s.binding.Images["nethub-authz"]
		if !acceptsWebReadiness(s.binding, image, c) {
			t.Fatal("reviewed Web container refused", external)
		}
		raw, _ := json.Marshal(c)
		for name, change := range map[string]func(*authorityContainer){
			"root":             func(c *authorityContainer) { c.Config.User = "0" },
			"shell":            func(c *authorityContainer) { c.Config.Entrypoint = []string{"/bin/sh"} },
			"wrong_image":      func(c *authorityContainer) { c.Image = "sha256:invalid" },
			"stopped":          func(c *authorityContainer) { c.State.Running = false },
			"unhealthy":        func(c *authorityContainer) { c.State.Health.Status = "unhealthy" },
			"privileged":       func(c *authorityContainer) { c.HostConfig.Privileged = true },
			"host_pid":         func(c *authorityContainer) { c.HostConfig.PidMode = "host" },
			"shared_authz_pid": func(c *authorityContainer) { c.HostConfig.PidMode = "container:authz" },
			"host_ipc":         func(c *authorityContainer) { c.HostConfig.IpcMode = "host" },
			"host_uts":         func(c *authorityContainer) { c.HostConfig.UTSMode = "host" },
			"host_userns":      func(c *authorityContainer) { c.HostConfig.UsernsMode = "host" },
			"device_mapping": func(c *authorityContainer) {
				c.HostConfig.Devices = []json.RawMessage{json.RawMessage(`{"PathOnHost":"/dev/fixture"}`)}
			},
			"unconfined": func(c *authorityContainer) {
				c.HostConfig.SecurityOpt = append(c.HostConfig.SecurityOpt, "seccomp=unconfined")
			},
			"capability":                func(c *authorityContainer) { c.HostConfig.CapAdd = []string{"SYS_ADMIN"} },
			"writable_root":             func(c *authorityContainer) { c.HostConfig.ReadonlyRootfs = false },
			"missing_no_new_privileges": func(c *authorityContainer) { c.HostConfig.SecurityOpt = nil },
			"environment_secret":        func(c *authorityContainer) { c.Config.Env = append(c.Config.Env, "FRP_TOKEN=fixture") },
			"other_project":             func(c *authorityContainer) { c.Config.Labels["com.docker.compose.project"] = "other" },
			"host_network":              func(c *authorityContainer) { c.HostConfig.NetworkMode = "host" },
			"writable_secret":           func(c *authorityContainer) { c.Mounts[0].RW = true },
			"authz_secrets":             func(c *authorityContainer) { c.Mounts[0].Source = "/srv/nethub/secrets/authz" },
			"broad_mount":               func(c *authorityContainer) { c.Mounts[0].Source = "/srv/nethub/secrets" },
			"extra_mount":               func(c *authorityContainer) { c.Mounts = append(c.Mounts, c.Mounts[0]) },
			"extra_network":             func(c *authorityContainer) { c.NetworkSettings.Networks["other"] = authorityNetwork{} },
			"public_port": func(c *authorityContainer) {
				c.HostConfig.PortBindings = map[string][]struct{ HostIP, HostPort string }{"8080/tcp": {{HostIP: "0.0.0.0", HostPort: "18080"}}}
			},
		} {
			t.Run(name, func(t *testing.T) {
				var bad authorityContainer
				if json.Unmarshal(raw, &bad) != nil {
					t.Fatal("fixture")
				}
				change(&bad)
				if acceptsWebReadiness(s.binding, image, bad) {
					t.Fatal("unsafe Web runtime accepted", external)
				}
			})
		}
	}
}
