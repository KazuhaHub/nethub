package guiissuer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
)

var dockerIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var dockerProjectPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// DockerBinding must come from independently verified local deployment state.
// A label alone is not authority to select a database container. Full immutable
// container/image identities fence replacement between invocations.
type DockerBinding struct{ ContainerID, ImageID, Project string }

func (b DockerBinding) valid() bool {
	return dockerIDPattern.MatchString(b.ContainerID) && len(b.ImageID) == 71 && b.ImageID[:7] == "sha256:" && dockerIDPattern.MatchString(b.ImageID[7:]) && dockerProjectPattern.MatchString(b.Project)
}

const databaseInspection = `{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"privileged":{{json .HostConfig.Privileged}},"network":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}}}`

func (b DockerBinding) accepts(data []byte) bool {
	if !b.valid() || len(data) > 4096 {
		return false
	}
	fields, err := boundedjson.Object(bytes.NewReader(data))
	if err != nil || len(fields) != 8 {
		return false
	}
	for _, key := range []string{"id", "image", "running", "project", "service", "privileged", "network", "ports"} {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	if !bytes.Equal(fields["running"], []byte("true")) || !bytes.Equal(fields["privileged"], []byte("false")) {
		return false
	}
	var value struct {
		ID, Image, Project, Service, Network string
		Running, Privileged                  bool
		Ports                                map[string]json.RawMessage
	}
	if json.Unmarshal(data, &value) != nil {
		return false
	}
	return value.ID == b.ContainerID && value.Image == b.ImageID && value.Project == b.Project && value.Service == "postgres" && value.Running && !value.Privileged && (value.Network == b.Project+"_database" || value.Network == "none") && len(value.Ports) == 0
}

type privateOutput struct {
	data     bytes.Buffer
	limit    int
	overflow bool
}

func (b *privateOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.data.Len() {
		b.overflow = true
		return 0, ErrDatabase
	}
	return b.data.Write(p)
}

func privateDockerCommand(ctx context.Context, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, "/usr/bin/docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
	// Do not inherit alternate daemon/context, PostgreSQL, proxy, credential or
	// tracing environment. Neither SQL nor private metadata enters arguments.
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	command.Stderr = io.Discard
	command.WaitDelay = 2 * time.Second
	return command
}

func privateDockerOutput(ctx context.Context, input []byte, limit int, args ...string) ([]byte, error) {
	command := privateDockerCommand(ctx, args...)
	command.Stdin = bytes.NewReader(input)
	output := privateOutput{limit: limit}
	command.Stdout = &output
	if command.Run() != nil || ctx.Err() != nil || output.overflow {
		return nil, ErrDatabase
	}
	return output.data.Bytes(), nil
}

// NewDockerSQLRunner never starts/reconfigures a container or reads a database
// password. Each call rechecks the exact private running postgres container,
// then uses its trusted local administrator socket and drops SQL session
// identity through SQLStore's fixed prefix. Root/the Docker daemon remain
// trusted; this is not confinement of a compromised privileged host.
func NewDockerSQLRunner(binding DockerBinding) (SQLRunner, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || !binding.valid() {
		return nil, ErrDatabase
	}
	return func(ctx context.Context, input []byte) ([]byte, error) {
		if len(input) == 0 || len(input) > 101000 || ctx.Err() != nil {
			return nil, ErrDatabase
		}
		bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		metadata, err := privateDockerOutput(bounded, nil, 4096, "inspect", "--type", "container", "--format", databaseInspection, binding.ContainerID)
		if err != nil || !binding.accepts(bytes.TrimSpace(metadata)) {
			return nil, ErrDatabase
		}
		return privateDockerOutput(bounded, input, 131072, "exec", "--interactive", "--user", "postgres", "--env", "PSQL_HISTORY=/dev/null", binding.ContainerID, "psql", "-X", "-qAt", "--host", "/var/run/postgresql", "--username", "postgres", "--dbname", "nethub", "--set", "ON_ERROR_STOP=1", "--set", "VERBOSITY=sqlstate")
	}, nil
}
