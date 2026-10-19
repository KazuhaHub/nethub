package setup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaycert"
	"github.com/KazuhaHub/nethub/server/internal/relaymaint"
)

type MaintenanceOptions struct {
	Directory, Project, ComposeFile string
	Retry                           bool
}

var projectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// MaintainRelay is a privileged host operation, never an HTTP signer endpoint.
func MaintainRelay(ctx context.Context, options MaintenanceOptions) (relaymaint.State, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || !projectName.MatchString(options.Project) {
		return relaymaint.State{}, errors.New("relay maintenance requires Linux root and a valid local project")
	}
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return relaymaint.State{}, relaymaint.ErrState
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory || CheckAuthority(directory) != nil {
		return relaymaint.State{}, relaymaint.ErrState
	}
	manifest, err := Load(directory)
	if err != nil || validateIdentity(manifest.Config) != nil {
		return relaymaint.State{}, relaymaint.ErrState
	}
	ca, err := os.ReadFile(filepath.Join(directory, "secrets/issuer/ca.pem"))
	if err != nil {
		return relaymaint.State{}, relaymaint.ErrState
	}
	key, err := os.ReadFile(filepath.Join(directory, "secrets/issuer/ca-key.pem"))
	if err != nil {
		return relaymaint.State{}, relaymaint.ErrState
	}
	trustPath := filepath.Join(directory, "runtime/trust/relay-ca.pem")
	runtimeInfo, err := os.Lstat(filepath.Join(directory, "runtime"))
	if err != nil || !runtimeInfo.IsDir() || runtimeInfo.Mode().Perm() != 0700 || ownerUID(filepath.Join(directory, "runtime")) != 0 {
		return relaymaint.State{}, relaymaint.ErrState
	}
	for _, path := range []string{filepath.Dir(trustPath), trustPath} {
		info, err := os.Lstat(path)
		mode := os.FileMode(0600)
		if path == filepath.Dir(trustPath) {
			mode = 0700
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || ownerUID(path) != 65532 || path == trustPath && (!info.Mode().IsRegular() || info.Size() > 32768) {
			return relaymaint.State{}, relaymaint.ErrState
		}
	}
	trust, err := os.ReadFile(trustPath)
	if err != nil || !bytes.Equal(trust, ca) {
		return relaymaint.State{}, relaymaint.ErrState
	}
	files := []string{filepath.Join(directory, "docker-compose.yml"), filepath.Join(directory, "docker-compose.override.yml")}
	if options.ComposeFile != "" {
		path, err := filepath.Abs(options.ComposeFile)
		if err != nil {
			return relaymaint.State{}, relaymaint.ErrState
		}
		files = append(files, path)
	}
	args := []string{"--host", "unix:///var/run/docker.sock", "compose", "--project-name", options.Project}
	for _, path := range files {
		actual, err := filepath.EvalSymlinks(path)
		info, statErr := os.Lstat(path)
		if err != nil || actual != path || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || ownerUID(path) != 0 || info.Size() > 262144 {
			return relaymaint.State{}, relaymaint.ErrState
		}
		args = append(args, "--file", path)
	}
	service := &relayHost{directory: directory, project: options.Project, args: args, ca: ca, name: manifest.Config.ConsoleHost}
	return (relaymaint.Engine{Directory: directory, Name: manifest.Config.ConsoleHost, CA: ca, CAKey: key, Service: service}).Run(ctx, options.Retry)
}

type relayHost struct {
	directory, project, name string
	args                     []string
	ca                       []byte
}
type commandBuffer struct{ data bytes.Buffer }

func (b *commandBuffer) Write(p []byte) (int, error) {
	size := len(p)
	if b.data.Len() < 65536 {
		remaining := 65536 - b.data.Len()
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.data.Write(p)
	}
	return size, nil
}

func (h *relayHost) command(ctx context.Context, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "docker", args...)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "DOCKER_") {
			command.Env = append(command.Env, value)
		}
	}
	var output commandBuffer
	command.Stdout = &output
	if command.Run() != nil {
		return nil, relaymaint.ErrMaintenance
	}
	return output.data.Bytes(), nil
}

func (h *relayHost) Running(ctx context.Context) (bool, error) {
	output, err := h.command(ctx, append(append([]string{}, h.args...), "ps", "--all", "--quiet", "frps")...)
	if err != nil {
		return false, err
	}
	ids := strings.Fields(string(output))
	if len(ids) == 0 {
		return false, relaymaint.ErrState
	}
	if len(ids) != 1 {
		return false, relaymaint.ErrState
	}
	if len(ids[0]) != 64 {
		return false, relaymaint.ErrState
	}
	if _, err := hex.DecodeString(ids[0]); err != nil {
		return false, relaymaint.ErrState
	}
	output, err = h.command(ctx, "--host", "unix:///var/run/docker.sock", "inspect", "--format", `{{ index .Config.Labels "com.docker.compose.project" }} {{ index .Config.Labels "com.docker.compose.service" }} {{ .State.Running }}`, ids[0])
	if err != nil {
		return false, err
	}
	fields := strings.Fields(string(output))
	if len(fields) != 3 || fields[0] != h.project || fields[1] != "frps" || fields[2] != "true" && fields[2] != "false" {
		return false, relaymaint.ErrState
	}
	metadata, err := h.command(ctx, "--host", "unix:///var/run/docker.sock", "inspect", "--format", `{"mounts":{{json .Mounts}},"command":{{json .Config.Cmd}},"user":{{json .Config.User}},"read_only":{{json .HostConfig.ReadonlyRootfs}},"network":{{json .HostConfig.NetworkMode}}}`, ids[0])
	if err != nil {
		return false, err
	}
	var configuration struct {
		Mounts []struct {
			Type, Source, Destination string
			RW                        bool
		} `json:"mounts"`
		Command  []string `json:"command"`
		User     string   `json:"user"`
		ReadOnly bool     `json:"read_only"`
		Network  string   `json:"network"`
	}
	if json.Unmarshal(metadata, &configuration) != nil || configuration.User != "65532:65532" || !configuration.ReadOnly || configuration.Network != "host" || len(configuration.Command) != 2 || configuration.Command[0] != "-c" || configuration.Command[1] != "/run/secrets/frps.toml" {
		return false, relaymaint.ErrState
	}
	expected := map[string]string{"/run/secrets": filepath.Join(h.directory, "secrets/frps"), "/run/relay": filepath.Join(h.directory, "runtime/relay")}
	for _, mount := range configuration.Mounts {
		source, ok := expected[mount.Destination]
		if !ok || mount.Type != "bind" || mount.RW || filepath.Clean(mount.Source) != source {
			return false, relaymaint.ErrState
		}
		delete(expected, mount.Destination)
	}
	if len(expected) != 0 {
		return false, relaymaint.ErrState
	}
	return fields[2] == "true", nil
}

func (h *relayHost) Current() ([]byte, []byte, error) {
	data, err := readRelayRuntime(h.directory, true)
	if err != nil || !bytes.Equal(data[2], h.ca) {
		return nil, nil, relaymaint.ErrState
	}
	return data[0], data[1], nil
}

func (h *relayHost) Publish(cert, key []byte) error {
	for name, data := range map[string][]byte{"relay-cert.pem": cert, "relay-key.pem": key} {
		path := filepath.Join(h.directory, "runtime/relay", name)
		if err := replaceRelayRuntime(path, data); err != nil {
			return err
		}
	}
	return nil
}

func replaceRelayRuntime(path string, data []byte) error {
	for _, dir := range []string{filepath.Dir(path), filepath.Dir(filepath.Dir(path))} {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
			return relaymaint.ErrState
		}
	}
	if ownerUID(filepath.Dir(path)) != 65532 {
		return relaymaint.ErrState
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600 || ownerUID(path) != 65532) {
		return relaymaint.ErrState
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".relay-*")
	if err != nil {
		return relaymaint.ErrState
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(data); err == nil {
		err = f.Chown(65532, 65532)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(temp, path) != nil {
		return relaymaint.ErrState
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return relaymaint.ErrState
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return relaymaint.ErrState
	}
	return nil
}

func (h *relayHost) Restart(ctx context.Context) error {
	_, err := h.command(ctx, append(append([]string{}, h.args...), "up", "--detach", "--no-build", "--no-deps", "--pull", "never", "--force-recreate", "frps")...)
	return err
}

func (h *relayHost) Observe(ctx context.Context) (string, error) {
	running, err := h.Running(ctx)
	if err != nil || !running {
		return "", relaymaint.ErrMaintenance
	}
	id, err := relaycert.Observe(ctx, netip.MustParseAddrPort("127.0.0.1:7000"), h.name, h.ca)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}
