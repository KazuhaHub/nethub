package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type backupReadinessVolume struct {
	Name, Driver, Scope, Mountpoint string
	Labels, Options                 map[string]string
}

type backupReadinessSnapshot struct {
	ContainerID string
	Image       authorityServiceImage
	Volume      backupReadinessVolume
}

func acceptsBackupVolumeMetadata(binding authorityServiceBinding, volume backupReadinessVolume) bool {
	return volume.Name == binding.Project+"_database-backups" && volume.Driver == "local" && volume.Scope == "local" && len(volume.Options) == 0 && filepath.IsAbs(volume.Mountpoint) && filepath.Clean(volume.Mountpoint) == volume.Mountpoint && volume.Labels["com.docker.compose.project"] == binding.Project && volume.Labels["com.docker.compose.volume"] == "database-backups"
}

func backupSecretDirectoryReady(directory string) bool {
	entries, err := os.ReadDir(filepath.Join(directory, "secrets/backup"))
	return err == nil && len(entries) == 1 && entries[0].Name() == "pg_nethub_backup" && entries[0].Type().IsRegular()
}

func acceptsBackupCommand(command []string) bool {
	if len(command) < 3 || len(command) > 10 || command[0] != "backup" || command[1] != "serve" {
		return false
	}
	seen := map[string]bool{}
	for i := 2; i < len(command); i++ {
		key, value, hasValue := strings.Cut(command[i], "=")
		if !hasValue {
			i++
			if i >= len(command) {
				return false
			}
			value = command[i]
		}
		if seen[key] || len(value) == 0 || len(value) > 64 {
			return false
		}
		seen[key] = true
		switch key {
		case "--sslmode":
			if value != "disable" {
				return false
			}
		case "--timeout":
			duration, err := time.ParseDuration(value)
			if err != nil || duration < time.Second || duration > 30*time.Minute {
				return false
			}
		case "--max-bytes":
			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil || size < 1024 || size > 1<<40 {
				return false
			}
		case "--retention-days":
			days, err := strconv.Atoi(value)
			if err != nil || days < 1 || days > 365 {
				return false
			}
		default:
			return false
		}
	}
	return seen["--sslmode"]
}

func acceptsBackupTmpfs(value string) bool {
	options := map[string]string{}
	for _, option := range strings.Split(value, ",") {
		key, setting, _ := strings.Cut(option, "=")
		if _, exists := options[key]; exists {
			return false
		}
		options[key] = setting
	}
	if len(options) != 8 {
		return false
	}
	for _, key := range []string{"rw", "noexec", "nosuid", "nodev"} {
		if value, exists := options[key]; !exists || value != "" {
			return false
		}
	}
	mode, err := strconv.ParseUint(options["mode"], 8, 32)
	if err != nil || mode != 0700 || options["uid"] != "65532" || options["gid"] != "65532" {
		return false
	}
	switch strings.ToLower(options["size"]) {
	case "1m", "1024k", "1048576":
		return true
	}
	return false
}

func acceptsBackupReadiness(binding authorityServiceBinding, image authorityServiceImage, volume backupReadinessVolume, command []string, c authorityContainer) bool {
	if !acceptsBackupVolumeMetadata(binding, volume) {
		return false
	}
	if !guiContainerID.MatchString(c.ID) || c.Image != image.ID || c.Config.User != "65532:65532" || !slices.Equal(c.Config.Entrypoint, []string{"/nethub"}) || !acceptsBackupCommand(command) || !slices.Equal(c.Config.Cmd, command) || !c.State.Running || c.State.Health == nil || c.State.Health.Status != "healthy" {
		return false
	}
	if c.HostConfig.Privileged || !c.HostConfig.ReadonlyRootfs || len(c.HostConfig.CapAdd) != 0 || !slices.Equal(c.HostConfig.CapDrop, []string{"ALL"}) || !slices.Equal(c.HostConfig.SecurityOpt, []string{"no-new-privileges:true"}) {
		return false
	}
	if c.HostConfig.PidMode != "" || c.HostConfig.UTSMode != "" || c.HostConfig.UsernsMode != "" || c.HostConfig.IpcMode != "" && c.HostConfig.IpcMode != "private" || len(c.HostConfig.Devices) != 0 || len(c.HostConfig.PortBindings) != 0 || len(c.Config.ExposedPorts) != 0 {
		return false
	}
	if c.HostConfig.NetworkMode != binding.Project+"_database" || len(c.NetworkSettings.Networks) != 1 {
		return false
	}
	if _, exists := c.NetworkSettings.Networks[binding.Project+"_database"]; !exists {
		return false
	}
	environment := append([]string(nil), c.Config.Env...)
	slices.Sort(environment)
	if !slices.Equal(environment, image.Environment) {
		return false
	}
	labels := c.Config.Labels
	if labels["com.docker.compose.project"] != binding.Project || labels["com.docker.compose.service"] != "backup" || labels["com.docker.compose.project.working_dir"] != binding.Directory {
		return false
	}
	health := c.Config.Healthcheck
	if health == nil || !slices.Equal(health.Test, []string{"CMD", "/nethub", "backup", "health"}) || health.Interval != 30*time.Second || health.Timeout != 10*time.Second || health.StartPeriod != 11*time.Minute || health.StartInterval != 0 && health.StartInterval != 5*time.Second || health.Retries != 3 {
		return false
	}
	if len(c.HostConfig.Tmpfs) != 1 || !acceptsBackupTmpfs(c.HostConfig.Tmpfs["/run/nethub-backup"]) {
		return false
	}
	if len(c.Mounts) < 2 || len(c.Mounts) > 3 {
		return false
	}
	seen := map[string]bool{}
	for _, mount := range c.Mounts {
		if seen[mount.Destination] {
			return false
		}
		seen[mount.Destination] = true
		switch mount.Destination {
		case "/run/secrets":
			if mount.Type != "bind" || mount.RW || mount.Source != filepath.Join(binding.Directory, "secrets/backup") {
				return false
			}
		case "/var/lib/nethub-backups":
			if mount.Type != "volume" || !mount.RW || mount.Source != volume.Mountpoint {
				return false
			}
		case "/run/nethub-backup":
			if mount.Type != "tmpfs" || !mount.RW || mount.Source != "" && mount.Source != "tmpfs" {
				return false
			}
		default:
			return false
		}
	}
	return seen["/run/secrets"] && seen["/var/lib/nethub-backups"]
}

func captureBackupReadiness(ctx context.Context, bound *BoundRelayAuthorityService) (backupReadinessSnapshot, error) {
	var snapshot backupReadinessSnapshot
	if !backupSecretDirectoryReady(bound.binding.Directory) {
		return snapshot, ErrContainerReadiness
	}
	raw, err := bound.command(ctx, append(append([]string{}, bound.host.compose...), "config", "--format", "json")...)
	var config struct {
		Services map[string]struct {
			Image       string
			Command     []string
			Environment map[string]any
		}
	}
	if err != nil || json.Unmarshal(raw, &config) != nil {
		return snapshot, ErrContainerReadiness
	}
	desired, exists := config.Services["backup"]
	if !exists || desired.Image == "" || len(desired.Environment) != 0 || !acceptsBackupCommand(desired.Command) {
		return snapshot, ErrContainerReadiness
	}
	raw, err = bound.command(ctx, "image", "inspect", "--format", `{"id":{{json .Id}},"environment":{{json .Config.Env}}}`, desired.Image)
	if err != nil || json.Unmarshal(raw, &snapshot.Image) != nil || len(snapshot.Image.ID) != 71 || !strings.HasPrefix(snapshot.Image.ID, "sha256:") || !guiContainerID.MatchString(snapshot.Image.ID[7:]) {
		return snapshot, ErrContainerReadiness
	}
	slices.Sort(snapshot.Image.Environment)
	raw, err = bound.command(ctx, "volume", "inspect", bound.binding.Project+"_database-backups")
	var volumes []backupReadinessVolume
	if err != nil || json.Unmarshal(raw, &volumes) != nil || len(volumes) != 1 {
		return snapshot, ErrContainerReadiness
	}
	volume := volumes[0]
	if !acceptsBackupVolumeMetadata(bound.binding, volume) {
		return snapshot, ErrContainerReadiness
	}
	actual, resolveErr := filepath.EvalSymlinks(volume.Mountpoint)
	info, statErr := os.Lstat(volume.Mountpoint)
	if !filepath.IsAbs(volume.Mountpoint) || resolveErr != nil || actual != volume.Mountpoint || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || ownerUID(volume.Mountpoint) != 65532 {
		return snapshot, ErrContainerReadiness
	}
	snapshot.Volume = volume
	raw, err = bound.command(ctx, append(append([]string{}, bound.host.compose...), "ps", "--all", "--quiet", "backup")...)
	snapshot.ContainerID = string(bytes.TrimSpace(raw))
	if err != nil || !guiContainerID.MatchString(snapshot.ContainerID) {
		return snapshot, ErrContainerReadiness
	}
	raw, err = bound.command(ctx, "inspect", "--type", "container", snapshot.ContainerID)
	var containers []authorityContainer
	if err != nil || json.Unmarshal(raw, &containers) != nil || len(containers) != 1 || containers[0].ID != snapshot.ContainerID || !acceptsBackupReadiness(bound.binding, snapshot.Image, volume, desired.Command, containers[0]) {
		return snapshot, ErrContainerReadiness
	}
	return snapshot, nil
}
