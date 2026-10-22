package setup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaycert"
)

type authorityServiceImage struct {
	ID          string   `json:"id"`
	Environment []string `json:"environment"`
}
type authorityServiceBinding struct {
	Version     int                              `json:"version"`
	Directory   string                           `json:"directory"`
	Project     string                           `json:"project"`
	Config      Config                           `json:"config"`
	ComposeHash string                           `json:"compose_sha256"`
	Files       map[string]string                `json:"files"`
	Images      map[string]authorityServiceImage `json:"images"`
}

// BoundRelayAuthorityService is a protected Docker-host adapter. Its immutable
// fingerprint must be bound into RelayAuthoritySnapshotOptions before running
// the transition; constructing a different binding cannot resume that journal.
type BoundRelayAuthorityService struct {
	host    guiHost
	binding authorityServiceBinding
	command func(context.Context, ...string) ([]byte, error)
}

func (s *BoundRelayAuthorityService) Fingerprint() string {
	return authorityHash(authorityJSON(s.binding))
}

func expectedAuthorityCommand(config Config, service string) []string {
	if service == "frps" {
		return []string{"-c", "/run/secrets/frps.toml"}
	}
	raw, err := composeOverride(config)
	if err != nil {
		return nil
	}
	var value struct {
		Services map[string]struct{ Command []string }
	}
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	return value.Services[service].Command
}

// BindRelayAuthorityService inspects only an existing protected deployment. It
// starts nothing, acquires no mutation lease and never initializes authority.
// Every later reload/observation rechecks this immutable configuration binding.
// Empty expectedFingerprint requires both services running with healthy authz.
// Recovery must pass the fingerprint from the protected operation's options;
// only that exact binding may recover stopped/unhealthy or absent containers.
func BindRelayAuthorityService(ctx context.Context, directory, project, composeFile, expectedFingerprint string) (*BoundRelayAuthorityService, error) {
	if os.Geteuid() != 0 || ctx.Err() != nil || !projectName.MatchString(project) || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrRelayAuthority
	}
	actual, err := filepath.EvalSymlinks(directory)
	info, statErr := os.Lstat(directory)
	if err != nil || actual != directory || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || ownerUID(directory) != 0 {
		return nil, ErrRelayAuthority
	}
	manifest, err := Load(directory)
	if err != nil || validateIdentity(manifest.Config) != nil || manifest.ConfirmedAt == nil {
		return nil, ErrRelayAuthority
	}
	host := guiHost{directory: directory, project: project, compose: []string{"compose", "--project-name", project}}
	binding := authorityServiceBinding{Version: 1, Directory: directory, Project: project, Config: manifest.Config, Files: map[string]string{}, Images: map[string]authorityServiceImage{}}
	files := []string{filepath.Join(directory, "docker-compose.yml"), filepath.Join(directory, "docker-compose.override.yml")}
	if composeFile != "" {
		files = append(files, composeFile)
	}
	for _, path := range files {
		raw, err := rootGUIFile(path, 262144, false)
		if err != nil {
			return nil, ErrRelayAuthority
		}
		if _, exists := binding.Files[path]; exists {
			return nil, ErrRelayAuthority
		}
		binding.Files[path] = authorityHash(raw)
		host.compose = append(host.compose, "--file", path)
	}
	s := &BoundRelayAuthorityService{host: host, binding: binding}
	s.command = host.docker
	raw, err := s.command(ctx, append(append([]string{}, host.compose...), "config", "--format", "json")...)
	if err != nil {
		return nil, ErrRelayAuthority
	}
	var config struct {
		Services map[string]struct {
			Image       string
			Command     []string
			Environment map[string]any
		}
	}
	if json.Unmarshal(raw, &config) != nil {
		return nil, ErrRelayAuthority
	}
	var canonical any
	if json.Unmarshal(raw, &canonical) != nil {
		return nil, ErrRelayAuthority
	}
	s.binding.ComposeHash = authorityHash(authorityJSON(canonical))
	for _, name := range []string{"nethub-authz", "frps"} {
		desired, ok := config.Services[name]
		if !ok || desired.Image == "" || !slices.Equal(desired.Command, expectedAuthorityCommand(manifest.Config, name)) || len(desired.Environment) != 0 {
			return nil, ErrRelayAuthority
		}
		raw, err := s.command(ctx, "image", "inspect", "--format", `{"id":{{json .Id}},"environment":{{json .Config.Env}}}`, desired.Image)
		var image authorityServiceImage
		if err != nil || json.Unmarshal(raw, &image) != nil || len(image.ID) != 71 || image.ID[:7] != "sha256:" || !guiContainerID.MatchString(image.ID[7:]) {
			return nil, ErrRelayAuthority
		}
		slices.Sort(image.Environment)
		s.binding.Images[name] = image
	}
	// Binding requires the original selected services to be running and authz
	// healthy. During later recovery the same valid containers may be stopped.
	if expectedFingerprint != "" && (!relayTrustDigest.MatchString(expectedFingerprint) || s.Fingerprint() != expectedFingerprint) {
		return nil, ErrRelayAuthority
	}
	requireRunning := expectedFingerprint == ""
	if err := s.check(ctx, requireRunning, requireRunning); err != nil {
		return nil, err
	}
	return s, nil
}

type authorityNetwork struct {
	IPAddress  string
	IPAMConfig *struct{ IPv4Address string }
}
type authorityContainer struct {
	ID     string `json:"Id"`
	Image  string
	Config struct {
		User                 string
		Cmd, Entrypoint, Env []string
		Labels               map[string]string
	}
	HostConfig struct {
		ReadonlyRootfs, Privileged   bool
		NetworkMode                  string
		CapDrop, CapAdd, SecurityOpt []string
		PortBindings                 map[string][]struct{ HostIP, HostPort string }
	}
	State struct {
		Running bool
		Health  *struct{ Status string }
	}
	Mounts []struct {
		Type, Source, Destination string
		RW                        bool
	}
	NetworkSettings struct {
		Networks map[string]authorityNetwork
	}
}

func (s *BoundRelayAuthorityService) accepts(name string, c authorityContainer, requireRunning, requireHealthy bool) bool {
	image, ok := s.binding.Images[name]
	if !ok || !guiContainerID.MatchString(c.ID) || c.Image != image.ID || c.Config.User != "65532:65532" || !c.HostConfig.ReadonlyRootfs || c.HostConfig.Privileged || !slices.Equal(c.HostConfig.CapDrop, []string{"ALL"}) || len(c.HostConfig.CapAdd) != 0 || !slices.Contains(c.HostConfig.SecurityOpt, "no-new-privileges:true") || !slices.Equal(c.Config.Cmd, expectedAuthorityCommand(s.binding.Config, name)) {
		return false
	}
	env := append([]string(nil), c.Config.Env...)
	slices.Sort(env)
	if !slices.Equal(env, image.Environment) || requireRunning && !c.State.Running {
		return false
	}
	labels := c.Config.Labels
	if labels["com.docker.compose.project"] != s.binding.Project || labels["com.docker.compose.service"] != name || labels["com.docker.compose.project.working_dir"] != s.binding.Directory {
		return false
	}
	expected := map[string]string{}
	if name == "frps" {
		if !slices.Equal(c.Config.Entrypoint, []string{"/frps"}) || c.HostConfig.NetworkMode != "host" || len(c.HostConfig.PortBindings) != 0 || len(c.NetworkSettings.Networks) != 1 {
			return false
		}
		if _, ok := c.NetworkSettings.Networks["host"]; !ok {
			return false
		}
		expected["/run/secrets"] = filepath.Join(s.binding.Directory, "secrets/frps")
		expected["/run/relay"] = filepath.Join(s.binding.Directory, "runtime/relay")
	} else {
		if !slices.Equal(c.Config.Entrypoint, []string{"/nethub"}) || c.HostConfig.NetworkMode != s.binding.Project+"_database" && c.HostConfig.NetworkMode != s.binding.Project+"_edge" || len(c.NetworkSettings.Networks) != 2 {
			return false
		}
		_, _, _, authz := edgeAddresses(s.binding.Config)
		edge, ok := c.NetworkSettings.Networks[s.binding.Project+"_edge"]
		if !ok || edge.IPAddress != authz && (c.State.Running || edge.IPAddress != "" || edge.IPAMConfig == nil || edge.IPAMConfig.IPv4Address != authz) {
			return false
		}
		if _, ok := c.NetworkSettings.Networks[s.binding.Project+"_database"]; !ok {
			return false
		}
		if requireHealthy && (c.State.Health == nil || c.State.Health.Status != "healthy") {
			return false
		}
		if s.binding.Config.externalProxy() {
			ports := c.HostConfig.PortBindings["8081/tcp"]
			_, port := s.binding.Config.originPorts()
			if len(c.HostConfig.PortBindings) != 1 || len(ports) != 1 || ports[0].HostIP != "127.0.0.1" || ports[0].HostPort != strconv.Itoa(int(port)) {
				return false
			}
		} else if len(c.HostConfig.PortBindings) != 0 {
			return false
		}
		expected["/run/secrets"] = filepath.Join(s.binding.Directory, "secrets/authz")
		expected["/run/trust"] = filepath.Join(s.binding.Directory, "runtime/trust")
	}
	for _, mount := range c.Mounts {
		source, ok := expected[mount.Destination]
		if !ok || mount.Type != "bind" || mount.RW || mount.Source != source {
			return false
		}
		delete(expected, mount.Destination)
	}
	return len(expected) == 0
}

func (s *BoundRelayAuthorityService) configuration(ctx context.Context) error {
	if s == nil || s.command == nil || ctx.Err() != nil {
		return ErrRelayAuthority
	}
	for path, digest := range s.binding.Files {
		raw, err := rootGUIFile(path, 262144, false)
		if err != nil || authorityHash(raw) != digest {
			return ErrRelayAuthority
		}
	}
	raw, err := s.command(ctx, append(append([]string{}, s.host.compose...), "config", "--format", "json")...)
	var config any
	if err != nil || json.Unmarshal(raw, &config) != nil || authorityHash(authorityJSON(config)) != s.binding.ComposeHash {
		return ErrRelayAuthority
	}
	// Resolve the same image reference again: a moved local tag must not pull a
	// different runtime into a recovery operation under an old snapshot digest.
	var desired struct {
		Services map[string]struct{ Image string }
	}
	if json.Unmarshal(raw, &desired) != nil {
		return ErrRelayAuthority
	}
	for name, image := range s.binding.Images {
		raw, err := s.command(ctx, "image", "inspect", "--format", "{{.Id}}", desired.Services[name].Image)
		if err != nil || string(bytes.TrimSpace(raw)) != image.ID {
			return ErrRelayAuthority
		}
	}
	return nil
}

func (s *BoundRelayAuthorityService) container(ctx context.Context, name string, running, healthy bool) error {
	ids, err := s.command(ctx, append(append([]string{}, s.host.compose...), "ps", "--all", "--quiet", name)...)
	id := string(bytes.TrimSpace(ids))
	// Compose may have removed the old container before a process interruption.
	// Only non-readiness recovery checks permit absence, after configuration and
	// image binding have passed. Initial bind/Observe still require actual IDs.
	if err == nil && id == "" && !running && !healthy {
		return nil
	}
	if err != nil || !guiContainerID.MatchString(id) {
		return ErrRelayAuthority
	}
	raw, err := s.command(ctx, "inspect", "--type", "container", id)
	var values []authorityContainer
	if err != nil || json.Unmarshal(raw, &values) != nil || len(values) != 1 || values[0].ID != id || !s.accepts(name, values[0], running, healthy) {
		return ErrRelayAuthority
	}
	return nil
}

func (s *BoundRelayAuthorityService) check(ctx context.Context, running, healthy bool) error {
	if s.configuration(ctx) != nil {
		return ErrRelayAuthority
	}
	for _, name := range []string{"nethub-authz", "frps"} {
		if s.container(ctx, name, running, healthy) != nil {
			return ErrRelayAuthority
		}
	}
	return nil
}

func (s *BoundRelayAuthorityService) Reload(ctx context.Context, ca []byte) error {
	bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if s.check(bounded, false, false) != nil {
		return ErrRelayAuthority
	}
	actual, err := authorityRead(filepath.Join(s.binding.Directory, "runtime/trust/relay-ca.pem"), 65532, 32768)
	if err != nil || !bytes.Equal(actual, ca) || CheckFiles(s.binding.Directory) != nil {
		return ErrRelayAuthority
	}
	for _, name := range []string{"nethub-authz", "frps"} {
		if s.configuration(bounded) != nil {
			return ErrRelayAuthority
		}
		args := append(append([]string{}, s.host.compose...), "up", "--detach", "--no-build", "--no-deps", "--pull", "never", "--force-recreate", name)
		if _, err := s.command(bounded, args...); err != nil {
			return ErrRelayAuthority
		}
		for {
			if s.container(bounded, name, true, true) == nil {
				break
			}
			select {
			case <-bounded.Done():
				return ErrRelayAuthority
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	for {
		if _, err := s.Observe(bounded, ca); err == nil {
			return nil
		}
		select {
		case <-bounded.Done():
			return ErrRelayAuthority
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (s *BoundRelayAuthorityService) Observe(ctx context.Context, ca []byte) (string, error) {
	if s.check(ctx, true, true) != nil {
		return "", ErrRelayAuthority
	}
	raw, err := authorityRead(filepath.Join(s.binding.Directory, "runtime/trust/relay-ca.pem"), 65532, 32768)
	if err != nil || !bytes.Equal(raw, ca) {
		return "", ErrRelayAuthority
	}
	value, err := relaycert.Observe(ctx, netip.MustParseAddrPort("127.0.0.1:7000"), s.binding.Config.ConsoleHost, ca)
	if err != nil {
		return "", ErrRelayAuthority
	}
	return hex.EncodeToString(value[:]), nil
}
