package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"
)

// CheckRuntimeContainers inspects an existing root-protected deployment through
// the local Docker socket. It never starts, executes inside or changes a service.
func CheckRuntimeContainers(ctx context.Context, directory, project, composeFile string) error {
	return checkRuntimeContainers(ctx, directory, project, composeFile, true)
}

// CheckRelayRuntimeContainers retains the Web/authz/frps prerequisite scope.
// Backup liveness is checked separately by the full container doctor.
func CheckRelayRuntimeContainers(ctx context.Context, directory, project, composeFile string) error {
	return checkRuntimeContainers(ctx, directory, project, composeFile, false)
}

func checkRuntimeContainers(ctx context.Context, directory, project, composeFile string, includeBackup bool) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if CheckFiles(directory) != nil {
		return ErrContainerReadiness
	}
	bound, err := BindRelayAuthorityService(ctx, directory, project, composeFile, "")
	if err != nil {
		return ErrContainerReadiness
	}
	var backupBefore backupReadinessSnapshot
	if includeBackup {
		backupBefore, err = captureBackupReadiness(ctx, bound)
		if err != nil {
			return ErrContainerReadiness
		}
	}
	// A correct mount source alone is insufficient if somebody copied another
	// service's credentials into the Web secret directory.
	if !webSecretDirectoryReady(directory) {
		return ErrContainerReadiness
	}
	raw, err := bound.command(ctx, append(append([]string{}, bound.host.compose...), "config", "--format", "json")...)
	var desired struct {
		Services map[string]struct {
			Image       string
			Command     []string
			Environment map[string]any
		}
	}
	if err != nil || json.Unmarshal(raw, &desired) != nil {
		return ErrContainerReadiness
	}
	web, ok := desired.Services["nethub-web"]
	if !ok || web.Image == "" || len(web.Environment) != 0 || !slices.Equal(web.Command, expectedAuthorityCommand(bound.binding.Config, "nethub-web")) {
		return ErrContainerReadiness
	}
	raw, err = bound.command(ctx, "image", "inspect", "--format", `{"id":{{json .Id}},"environment":{{json .Config.Env}}}`, web.Image)
	var image authorityServiceImage
	if err != nil || json.Unmarshal(raw, &image) != nil || len(image.ID) != 71 || image.ID[:7] != "sha256:" || !guiContainerID.MatchString(image.ID[7:]) {
		return ErrContainerReadiness
	}
	slices.Sort(image.Environment)
	raw, err = bound.command(ctx, append(append([]string{}, bound.host.compose...), "ps", "--all", "--quiet", "nethub-web")...)
	id := string(bytes.TrimSpace(raw))
	if err != nil || !guiContainerID.MatchString(id) {
		return ErrContainerReadiness
	}
	raw, err = bound.command(ctx, "inspect", "--type", "container", id)
	var containers []authorityContainer
	if err != nil || json.Unmarshal(raw, &containers) != nil || len(containers) != 1 || containers[0].ID != id || !acceptsWebReadiness(bound.binding, image, containers[0]) {
		return ErrContainerReadiness
	}
	// Detect service/configuration changes during observation rather than
	// reporting the initial healthy authz/frps check as a final current result.
	if bound.check(ctx, true, true) != nil {
		return ErrContainerReadiness
	}
	raw, err = bound.command(ctx, "image", "inspect", "--format", "{{.Id}}", web.Image)
	if err != nil || string(bytes.TrimSpace(raw)) != image.ID {
		return ErrContainerReadiness
	}
	raw, err = bound.command(ctx, append(append([]string{}, bound.host.compose...), "ps", "--all", "--quiet", "nethub-web")...)
	if err != nil || string(bytes.TrimSpace(raw)) != id {
		return ErrContainerReadiness
	}
	raw, err = bound.command(ctx, "inspect", "--type", "container", id)
	containers = nil
	if err != nil || json.Unmarshal(raw, &containers) != nil || len(containers) != 1 || containers[0].ID != id || !acceptsWebReadiness(bound.binding, image, containers[0]) {
		return ErrContainerReadiness
	}
	if includeBackup {
		after, err := captureBackupReadiness(ctx, bound)
		if err != nil || !bytes.Equal(authorityJSON(backupBefore), authorityJSON(after)) {
			return ErrContainerReadiness
		}
	}
	if CheckFiles(directory) != nil || !webSecretDirectoryReady(directory) || includeBackup && !backupSecretDirectoryReady(directory) {
		return ErrContainerReadiness
	}
	return nil
}

func webSecretDirectoryReady(directory string) bool {
	entries, err := os.ReadDir(filepath.Join(directory, "secrets/web"))
	if err != nil || len(entries) != 2 {
		return false
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || entry.Name() != "pg_nethub_web" && entry.Name() != "secrets_key" {
			return false
		}
	}
	return true
}

func acceptsWebReadiness(binding authorityServiceBinding, image authorityServiceImage, c authorityContainer) bool {
	if !guiContainerID.MatchString(c.ID) || c.Image != image.ID || c.Config.User != "65532:65532" || !slices.Equal(c.Config.Entrypoint, []string{"/nethub"}) || !slices.Equal(c.Config.Cmd, expectedAuthorityCommand(binding.Config, "nethub-web")) || !c.State.Running || c.State.Health == nil || c.State.Health.Status != "healthy" {
		return false
	}
	if c.HostConfig.Privileged || !c.HostConfig.ReadonlyRootfs || len(c.HostConfig.CapAdd) != 0 || !slices.Equal(c.HostConfig.CapDrop, []string{"ALL"}) || !slices.Contains(c.HostConfig.SecurityOpt, "no-new-privileges:true") {
		return false
	}
	env := append([]string(nil), c.Config.Env...)
	if c.HostConfig.PidMode != "" || c.HostConfig.UTSMode != "" || c.HostConfig.UsernsMode != "" || c.HostConfig.IpcMode != "" && c.HostConfig.IpcMode != "private" || len(c.HostConfig.Devices) != 0 || len(c.HostConfig.SecurityOpt) != 1 {
		return false
	}
	slices.Sort(env)
	if !slices.Equal(env, image.Environment) {
		return false
	}
	labels := c.Config.Labels
	if labels["com.docker.compose.project"] != binding.Project || labels["com.docker.compose.service"] != "nethub-web" || labels["com.docker.compose.project.working_dir"] != binding.Directory {
		return false
	}
	if len(c.Mounts) != 1 {
		return false
	}
	mount := c.Mounts[0]
	if mount.Type != "bind" || mount.RW || mount.Destination != "/run/secrets" || mount.Source != filepath.Join(binding.Directory, "secrets/web") {
		return false
	}
	if c.HostConfig.NetworkMode != binding.Project+"_database" && c.HostConfig.NetworkMode != binding.Project+"_edge" || len(c.NetworkSettings.Networks) != 2 {
		return false
	}
	if _, ok := c.NetworkSettings.Networks[binding.Project+"_database"]; !ok {
		return false
	}
	_, _, webIP, _ := edgeAddresses(binding.Config)
	if edge, ok := c.NetworkSettings.Networks[binding.Project+"_edge"]; !ok || edge.IPAddress != webIP {
		return false
	}
	if !binding.Config.externalProxy() {
		return len(c.HostConfig.PortBindings) == 0
	}
	port, _ := binding.Config.originPorts()
	ports := c.HostConfig.PortBindings["8080/tcp"]
	return len(c.HostConfig.PortBindings) == 1 && len(ports) == 1 && ports[0].HostIP == "127.0.0.1" && ports[0].HostPort == strconv.Itoa(int(port))
}
