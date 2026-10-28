package setup

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupReadinessRejectsExcessAuthority(t *testing.T) {
	s, c := authorityServiceFixture(t, "nethub-authz", false)
	image := s.binding.Images["nethub-authz"]
	volume := backupReadinessVolume{Name: "fixture_database-backups", Driver: "local", Scope: "local", Mountpoint: "/var/lib/docker/volumes/fixture_database-backups/_data", Labels: map[string]string{"com.docker.compose.project": "fixture", "com.docker.compose.volume": "database-backups"}}
	command := []string{"backup", "serve", "--sslmode", "disable"}
	c.Config.Cmd = command
	c.Config.Labels["com.docker.compose.service"] = "backup"
	c.Config.Healthcheck = &authorityHealthcheck{Test: []string{"CMD", "/nethub", "backup", "health"}, Interval: 30 * time.Second, Timeout: 10 * time.Second, StartPeriod: 11 * time.Minute, Retries: 3}
	c.HostConfig.PortBindings = nil
	c.HostConfig.Tmpfs = map[string]string{"/run/nethub-backup": "rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=65532,gid=65532"}
	c.NetworkSettings.Networks = map[string]authorityNetwork{"fixture_database": {}}
	c.Mounts = c.Mounts[:1]
	c.Mounts[0].Type = "bind"
	c.Mounts[0].Source = filepath.Join(s.binding.Directory, "secrets/backup")
	c.Mounts[0].Destination = "/run/secrets"
	c.Mounts[0].RW = false
	archive := c.Mounts[0]
	archive.Type = "volume"
	archive.Source = volume.Mountpoint
	archive.Destination = "/var/lib/nethub-backups"
	archive.RW = true
	c.Mounts = append(c.Mounts, archive)
	if !acceptsBackupReadiness(s.binding, image, volume, command, c) {
		t.Fatal("reviewed backup container refused")
	}
	raw, _ := json.Marshal(c)
	for name, change := range map[string]func(*authorityContainer){
		"root":           func(c *authorityContainer) { c.Config.User = "0" },
		"shell":          func(c *authorityContainer) { c.Config.Entrypoint = []string{"/bin/sh"} },
		"stopped":        func(c *authorityContainer) { c.State.Running = false },
		"unhealthy":      func(c *authorityContainer) { c.State.Health.Status = "unhealthy" },
		"fake_health":    func(c *authorityContainer) { c.Config.Healthcheck.Test = []string{"CMD", "/nethub", "version"} },
		"slow_health":    func(c *authorityContainer) { c.Config.Healthcheck.Interval = time.Hour },
		"missing_health": func(c *authorityContainer) { c.Config.Healthcheck = nil },
		"image":          func(c *authorityContainer) { c.Image = "sha256:invalid" },
		"environment":    func(c *authorityContainer) { c.Config.Env = append(c.Config.Env, "PGPASSWORD=fixture") },
		"privileged":     func(c *authorityContainer) { c.HostConfig.Privileged = true },
		"capability":     func(c *authorityContainer) { c.HostConfig.CapAdd = []string{"SYS_ADMIN"} },
		"writable_root":  func(c *authorityContainer) { c.HostConfig.ReadonlyRootfs = false },
		"host_pid":       func(c *authorityContainer) { c.HostConfig.PidMode = "host" },
		"host_ipc":       func(c *authorityContainer) { c.HostConfig.IpcMode = "host" },
		"host_uts":       func(c *authorityContainer) { c.HostConfig.UTSMode = "host" },
		"host_userns":    func(c *authorityContainer) { c.HostConfig.UsernsMode = "host" },
		"device": func(c *authorityContainer) {
			c.HostConfig.Devices = []json.RawMessage{json.RawMessage(`{"PathOnHost":"/dev/fixture"}`)}
		},
		"unconfined": func(c *authorityContainer) {
			c.HostConfig.SecurityOpt = append(c.HostConfig.SecurityOpt, "seccomp=unconfined")
		},
		"missing_no_new_privileges": func(c *authorityContainer) { c.HostConfig.SecurityOpt = nil },
		"edge_network":              func(c *authorityContainer) { c.NetworkSettings.Networks["fixture_edge"] = authorityNetwork{} },
		"host_network":              func(c *authorityContainer) { c.HostConfig.NetworkMode = "host" },
		"exposed_postgres": func(c *authorityContainer) {
			c.Config.ExposedPorts = map[string]json.RawMessage{"5432/tcp": json.RawMessage(`{}`)}
		},
		"writable_password": func(c *authorityContainer) { c.Mounts[0].RW = true },
		"authz_password":    func(c *authorityContainer) { c.Mounts[0].Source = filepath.Join(s.binding.Directory, "secrets/authz") },
		"foreign_archive":   func(c *authorityContainer) { c.Mounts[1].Source = "/srv/foreign" },
		"archive_bind":      func(c *authorityContainer) { c.Mounts[1].Type = "bind" },
		"extra_mount":       func(c *authorityContainer) { c.Mounts = append(c.Mounts, c.Mounts[0]) },
		"public_runtime": func(c *authorityContainer) {
			c.HostConfig.Tmpfs["/run/nethub-backup"] = strings.ReplaceAll(c.HostConfig.Tmpfs["/run/nethub-backup"], "mode=0700", "mode=0777")
		},
		"executable_runtime": func(c *authorityContainer) {
			c.HostConfig.Tmpfs["/run/nethub-backup"] = strings.ReplaceAll(c.HostConfig.Tmpfs["/run/nethub-backup"], "noexec", "exec")
		},
		"other_project": func(c *authorityContainer) { c.Config.Labels["com.docker.compose.project"] = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			var bad authorityContainer
			if json.Unmarshal(raw, &bad) != nil {
				t.Fatal("fixture")
			}
			change(&bad)
			if acceptsBackupReadiness(s.binding, image, volume, command, bad) {
				t.Fatal("unsafe backup authority accepted")
			}
		})
	}
	for _, command := range [][]string{{"backup", "serve", "--sslmode=disable", "--timeout", "5m", "--max-bytes", "4096", "--retention-days", "7"}, {"backup", "serve", "--sslmode", "disable"}} {
		if !acceptsBackupCommand(command) {
			t.Fatal("bounded backup options refused")
		}
	}
	for _, command := range [][]string{{"backup", "run", "--sslmode", "disable"}, {"backup", "serve", "--sslmode", "disable", "--host", "other"}, {"backup", "serve", "--sslmode", "disable", "--sslmode", "disable"}, {"backup", "serve", "--sslmode", "disable", "--timeout", "31m"}, {"backup", "serve", "--sslmode", "disable", "--retention-days", "0"}} {
		if acceptsBackupCommand(command) {
			t.Fatal("unreviewed backup command accepted")
		}
	}
	for _, value := range []string{"rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=0,gid=65532", "rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=65532,gid=65532,exec"} {
		if acceptsBackupTmpfs(value) {
			t.Fatal("unsafe tmpfs accepted")
		}
	}
	for name, change := range map[string]func(*backupReadinessVolume){"foreign_project": func(v *backupReadinessVolume) { v.Labels["com.docker.compose.project"] = "other" }, "foreign_name": func(v *backupReadinessVolume) { v.Name = "other_database-backups" }, "remote_driver": func(v *backupReadinessVolume) { v.Driver = "remote" }, "bind_options": func(v *backupReadinessVolume) { v.Options = map[string]string{"device": "/srv/other"} }} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(volume)
			var bad backupReadinessVolume
			_ = json.Unmarshal(raw, &bad)
			change(&bad)
			if acceptsBackupVolumeMetadata(s.binding, bad) {
				t.Fatal("foreign volume accepted")
			}
		})
	}
}
