package setup

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func authorityServiceFixture(t *testing.T, name string, external bool) (*BoundRelayAuthorityService, authorityContainer) {
	t.Helper()
	config := fixtureConfig(t)
	if external {
		config.ProxyMode = "external"
	}
	directory := "/srv/nethub"
	image := authorityServiceImage{ID: "sha256:" + strings.Repeat("a", 64), Environment: []string{"PATH=/usr/bin"}}
	s := &BoundRelayAuthorityService{binding: authorityServiceBinding{Version: 1, Directory: directory, Project: "fixture", Config: config, Images: map[string]authorityServiceImage{name: image}}}
	var c authorityContainer
	c.ID = strings.Repeat("b", 64)
	c.Image = image.ID
	c.Config.User = "65532:65532"
	c.Config.Cmd = expectedAuthorityCommand(config, name)
	c.Config.Env = append([]string(nil), image.Environment...)
	c.Config.Labels = map[string]string{"com.docker.compose.project": "fixture", "com.docker.compose.service": name, "com.docker.compose.project.working_dir": directory}
	c.HostConfig.ReadonlyRootfs = true
	c.HostConfig.CapDrop = []string{"ALL"}
	c.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	c.State.Running = true
	c.NetworkSettings.Networks = map[string]authorityNetwork{}
	mounts := map[string]string{}
	if name == "frps" {
		c.Config.Entrypoint = []string{"/frps"}
		c.HostConfig.NetworkMode = "host"
		c.NetworkSettings.Networks["host"] = authorityNetwork{}
		mounts["/run/secrets"] = "secrets/frps"
		mounts["/run/relay"] = "runtime/relay"
	} else {
		c.Config.Entrypoint = []string{"/nethub"}
		c.HostConfig.NetworkMode = "fixture_database"
		_, _, _, ip := edgeAddresses(config)
		c.NetworkSettings.Networks["fixture_database"] = authorityNetwork{}
		c.NetworkSettings.Networks["fixture_edge"] = authorityNetwork{IPAddress: ip}
		c.State.Health = &struct{ Status string }{Status: "healthy"}
		mounts["/run/secrets"] = "secrets/authz"
		mounts["/run/trust"] = "runtime/trust"
		if external {
			c.HostConfig.PortBindings = map[string][]struct{ HostIP, HostPort string }{"8081/tcp": {{HostIP: "127.0.0.1", HostPort: "18081"}}}
		}
	}
	for target, source := range mounts {
		c.Mounts = append(c.Mounts, struct {
			Type, Source, Destination string
			RW                        bool
		}{Type: "bind", Source: filepath.Join(directory, source), Destination: target})
	}
	return s, c
}

func TestAuthorityServiceBindingChecksActualRuntimeAuthority(t *testing.T) {
	for _, name := range []string{"nethub-authz", "frps"} {
		t.Run(name, func(t *testing.T) {
			s, base := authorityServiceFixture(t, name, false)
			if !s.accepts(name, base, true, true) {
				t.Fatal("expected service refused")
			}
			changes := []func(*authorityContainer){
				func(c *authorityContainer) { c.ID = "invalid" }, func(c *authorityContainer) { c.Image = "sha256:" + strings.Repeat("c", 64) },
				func(c *authorityContainer) { c.Config.User = "0" }, func(c *authorityContainer) { c.Config.Cmd = []string{"other"} },
				func(c *authorityContainer) { c.Config.Entrypoint = []string{"/bin/sh"} }, func(c *authorityContainer) { c.Config.Env = append(c.Config.Env, "PGHOST=other") },
				func(c *authorityContainer) { c.Config.Labels["com.docker.compose.project"] = "other" }, func(c *authorityContainer) { c.Config.Labels["com.docker.compose.project.working_dir"] = "/other" },
				func(c *authorityContainer) { c.HostConfig.Privileged = true }, func(c *authorityContainer) { c.HostConfig.ReadonlyRootfs = false },
				func(c *authorityContainer) { c.HostConfig.CapDrop = nil }, func(c *authorityContainer) { c.HostConfig.CapAdd = []string{"SYS_ADMIN"} },
				func(c *authorityContainer) { c.HostConfig.SecurityOpt = nil }, func(c *authorityContainer) { c.HostConfig.NetworkMode = "none" },
				func(c *authorityContainer) { c.Mounts[0].RW = true }, func(c *authorityContainer) { c.Mounts[0].Source = "/other" }, func(c *authorityContainer) { c.Mounts = c.Mounts[:1] },
				func(c *authorityContainer) { c.State.Running = false },
			}
			raw, _ := json.Marshal(base)
			for i, change := range changes {
				var bad authorityContainer
				if json.Unmarshal(raw, &bad) != nil {
					t.Fatal("fixture")
				}
				change(&bad)
				if s.accepts(name, bad, true, true) {
					t.Fatal("unsafe service accepted", i)
				}
			}
			base.State.Running = false
			if !s.accepts(name, base, false, false) {
				t.Fatal("recovery binding refused unchanged stopped service")
			}
		})
	}
	s, c := authorityServiceFixture(t, "nethub-authz", true)
	if !s.accepts("nethub-authz", c, true, true) {
		t.Fatal("external proxy binding refused")
	}
	c.HostConfig.PortBindings["8081/tcp"][0].HostIP = "0.0.0.0"
	if s.accepts("nethub-authz", c, true, true) {
		t.Fatal("public origin binding accepted")
	}
}

func TestAuthorityServiceFingerprintBindsImmutableConfiguration(t *testing.T) {
	s, _ := authorityServiceFixture(t, "frps", false)
	original := s.Fingerprint()
	s.binding.Project = "other"
	if original == s.Fingerprint() {
		t.Fatal("service drift did not change fingerprint")
	}
}

func TestStoppedAuthorityServiceRequiresRetainedStaticNetwork(t *testing.T) {
	s, c := authorityServiceFixture(t, "nethub-authz", false)
	c.State.Running = false
	edge := c.NetworkSettings.Networks["fixture_edge"]
	ip := edge.IPAddress
	edge.IPAddress = ""
	c.NetworkSettings.Networks["fixture_edge"] = edge
	if s.accepts("nethub-authz", c, false, false) {
		t.Fatal("stopped service without retained network identity accepted")
	}
	edge.IPAMConfig = &struct{ IPv4Address string }{IPv4Address: ip}
	c.NetworkSettings.Networks["fixture_edge"] = edge
	if !s.accepts("nethub-authz", c, false, false) {
		t.Fatal("unchanged stopped static network refused")
	}
	if s.accepts("nethub-authz", c, true, true) {
		t.Fatal("stopped service counted as ready")
	}
}

func TestProductionAuthorityHostRequiresPinnedServiceFingerprint(t *testing.T) {
	service, _ := authorityServiceFixture(t, "frps", false)
	host := &RelayAuthoritySnapshotHost{Service: service}
	if host.checkServiceBinding() == nil {
		t.Fatal("production service attached without snapshot fingerprint")
	}
	host.Options.ServiceFingerprint = service.Fingerprint()
	if host.checkServiceBinding() != nil {
		t.Fatal("exact production binding refused")
	}
	service.binding.Project = "other"
	if host.checkServiceBinding() == nil {
		t.Fatal("rebound service attached to old operation")
	}
}
