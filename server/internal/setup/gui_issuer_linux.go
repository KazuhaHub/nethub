package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiacme"
	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/KazuhaHub/nethub/server/internal/http01"
	"golang.org/x/sys/unix"
)

func guiRootFile(info os.FileInfo) bool {
	v, ok := info.Sys().(*syscall.Stat_t)
	return ok && v.Uid == 0 && v.Nlink == 1
}

type GUIIssuerResult struct {
	State string `json:"state"`
	Steps int    `json:"steps"`
}
type guiHost struct {
	directory, project string
	compose            []string
}
type guiOutput struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (o *guiOutput) Write(p []byte) (int, error) {
	if len(p) > o.limit-o.Len() {
		o.overflow = true
		return 0, ErrGUIIssuer
	}
	return o.Buffer.Write(p)
}

func guiHostCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, binary, args...)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	command.Stderr = io.Discard
	command.WaitDelay = 2 * time.Second
	output := guiOutput{limit: 262144}
	command.Stdout = &output
	if command.Run() != nil || bounded.Err() != nil || output.overflow {
		return nil, ErrGUIIssuer
	}
	return bytes.TrimSpace(output.Bytes()), nil
}

func (h guiHost) docker(ctx context.Context, args ...string) ([]byte, error) {
	return guiHostCommand(ctx, "/usr/bin/docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
}

var guiContainerID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (h guiHost) database(ctx context.Context) (guiissuer.DockerBinding, error) {
	raw, err := h.docker(ctx, append(append([]string{}, h.compose...), "config", "--format", "json")...)
	if err != nil {
		return guiissuer.DockerBinding{}, err
	}
	var config struct {
		Services map[string]struct{ Image string }
	}
	if json.Unmarshal(raw, &config) != nil || config.Services["postgres"].Image == "" {
		return guiissuer.DockerBinding{}, ErrGUIIssuer
	}
	image := config.Services["postgres"].Image
	if len(image) > 512 || strings.HasPrefix(image, "-") || strings.ContainsAny(image, "\x00\r\n ") {
		return guiissuer.DockerBinding{}, ErrGUIIssuer
	}
	imageID, err := h.docker(ctx, "image", "inspect", "--format", "{{.Id}}", image)
	if err != nil {
		return guiissuer.DockerBinding{}, err
	}
	id, err := h.docker(ctx, append(append([]string{}, h.compose...), "ps", "--all", "--quiet", "postgres")...)
	if err != nil || !guiContainerID.Match(id) {
		return guiissuer.DockerBinding{}, ErrGUIIssuer
	}
	binding := guiissuer.DockerBinding{ContainerID: string(id), ImageID: string(imageID), Project: h.project}
	metadata, err := h.docker(ctx, "inspect", "--type", "container", "--format", `{"mounts":{{json .Mounts}},"working_dir":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}}}`, binding.ContainerID)
	if err != nil || !guiDatabaseMounts(metadata, h.directory, h.project) {
		return guiissuer.DockerBinding{}, ErrGUIIssuer
	}
	volume, err := h.docker(ctx, "volume", "inspect", "--format", `{{index .Labels "com.docker.compose.project"}}|{{index .Labels "com.docker.compose.volume"}}`, h.project+"_database")
	if err != nil || string(volume) != h.project+"|database" {
		return guiissuer.DockerBinding{}, ErrGUIIssuer
	}
	return binding, nil
}

func guiDatabaseMounts(data []byte, directory, project string) bool {
	var m struct {
		WorkingDir string `json:"working_dir"`
		Mounts     []struct {
			Type, Source, Destination, Name string
			RW                              bool
		}
	}
	if json.Unmarshal(data, &m) != nil || m.WorkingDir != directory || len(m.Mounts) != 3 {
		return false
	}
	expected := map[string]string{"/run/secrets": filepath.Join(directory, "secrets/postgres"), "/docker-entrypoint-initdb.d/00-nethub-roles.sh": filepath.Join(directory, "00-nethub-roles.sh")}
	volume := false
	for _, mount := range m.Mounts {
		if mount.Destination == "/var/lib/postgresql/data" {
			if volume || mount.Type != "volume" || mount.Name != project+"_database" || !mount.RW {
				return false
			}
			volume = true
			continue
		}
		source, ok := expected[mount.Destination]
		if !ok || mount.Type != "bind" || mount.RW || mount.Source != source {
			return false
		}
		delete(expected, mount.Destination)
	}
	return volume && len(expected) == 0
}

func guiCleanupReady(ctx context.Context, publisher *http01.Publisher, timer string) error {
	data, err := guiHostCommand(ctx, "/usr/bin/systemctl", "show", timer, "--property=ActiveState,Unit")
	if err != nil {
		return ErrGUIIssuer
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ErrGUIIssuer
		}
		values[key] = value
	}
	service := strings.TrimSuffix(timer, ".timer") + ".service"
	if values["ActiveState"] != "active" || values["Unit"] != service {
		return ErrGUIIssuer
	}
	data, err = guiHostCommand(ctx, "/usr/bin/systemctl", "show", service, "--property=Result", "--value")
	if err != nil || string(data) != "success" || publisher.CleanupReady(time.Now()) != nil {
		return ErrGUIIssuer
	}
	return nil
}

type checkedGUIPublisher struct {
	publisher *http01.Publisher
	timer     string
}

func (p checkedGUIPublisher) Publish(ctx context.Context, v http01.Publication) error {
	if guiCleanupReady(ctx, p.publisher, p.timer) != nil {
		return ErrGUIIssuer
	}
	return p.publisher.Publish(ctx, v)
}
func (p checkedGUIPublisher) Remove(ctx context.Context, host, generation string) error {
	return p.publisher.Remove(ctx, host, generation)
}

// RunGUIIssuer advances one current job in an existing protected deployment.
// It does not initialize accounts, enable services, mutate the appliance or
// select a database by labels alone. Root and the local daemon remain trusted.
func RunGUIIssuer(ctx context.Context, options GUIIssuerOptions) (GUIIssuerResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	result := GUIIssuerResult{}
	if os.Geteuid() != 0 || !projectName.MatchString(options.Project) {
		return result, ErrGUIIssuer
	}
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return result, ErrGUIIssuer
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory || CheckAuthority(directory) != nil {
		return result, ErrGUIIssuer
	}
	manifest, err := Load(directory)
	if err != nil || validateIdentity(manifest.Config) != nil {
		return result, ErrGUIIssuer
	}
	data, err := rootGUIFile(options.ConfigFile, 32768, true)
	if err != nil {
		return result, err
	}
	policy, err := decodeGUIIssuerPolicy(data)
	if err != nil {
		return result, err
	}
	runtimeDir := filepath.Join(directory, "runtime")
	info, err := os.Lstat(runtimeDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || ownerUID(runtimeDir) != 0 {
		return result, ErrGUIIssuer
	}
	lockPath := filepath.Join(runtimeDir, "gui-issuer.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	var previous os.FileInfo
	if os.IsExist(err) {
		previous, err = os.Lstat(lockPath)
		if err != nil || !previous.Mode().IsRegular() || !guiRootFile(previous) || previous.Mode().Perm() != 0600 || previous.Size() != 0 {
			return result, ErrGUIIssuer
		}
		lock, err = os.OpenFile(lockPath, os.O_RDWR, 0)
	} else if err == nil {
		err = lock.Chmod(0600)
	}
	if err != nil {
		if lock != nil {
			lock.Close()
		}
		return result, ErrGUIIssuer
	}
	defer lock.Close()
	info, err = lock.Stat()
	if err != nil || !guiRootFile(info) || info.Mode().Perm() != 0600 || info.Size() != 0 || previous != nil && !os.SameFile(previous, info) {
		return result, ErrGUIIssuer
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return result, ErrGUIIssuerBusy
		}
		return result, ErrGUIIssuer
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	publisher, err := http01.OpenExistingFile(policy.HTTPPolicyFile)
	if errors.Is(err, http01.ErrBusy) {
		return result, ErrGUIIssuerBusy
	}
	if err != nil || !publisher.MatchesPolicy(manifest.Config.DeviceDomain, []string{manifest.Config.ConsoleHost}) {
		return result, ErrGUIIssuer
	}
	if guiCleanupReady(ctx, publisher, policy.CleanupTimer) != nil {
		return result, ErrGUIIssuer
	}
	roots, err := guiTrustRoots(policy.CertificateRootsFile)
	if err != nil {
		return result, err
	}
	apiRoots, err := guiTrustRoots(policy.APIRootsFile)
	if err != nil {
		return result, err
	}
	account, err := guiacme.NewAccountStore(policy.AccountDirectory, guiacme.Config{DirectoryURL: policy.DirectoryURL, ContactEmail: policy.ContactEmail, AdditionalOrigins: policy.AdditionalOrigins, Roots: apiRoots})
	if err != nil || account.Ready(ctx) != nil {
		return result, ErrGUIIssuer
	}
	host := guiHost{directory: directory, project: options.Project, compose: []string{"compose", "--project-name", options.Project}}
	files := []string{filepath.Join(directory, "docker-compose.yml"), filepath.Join(directory, "docker-compose.override.yml")}
	if options.ComposeFile != "" {
		files = append(files, options.ComposeFile)
	}
	for _, file := range files {
		if _, err := rootGUIFile(file, 262144, false); err != nil {
			return result, err
		}
		host.compose = append(host.compose, "--file", file)
	}
	binding, err := host.database(ctx)
	if err != nil {
		return result, err
	}
	run, err := guiissuer.NewDockerSQLRunner(binding)
	if err != nil {
		return result, ErrGUIIssuer
	}
	store := &guiissuer.SQLStore{Run: run, Domain: manifest.Config.DeviceDomain, Excluded: []string{manifest.Config.ConsoleHost}, AllowsURL: account.AllowsURL}
	if store.Ready(ctx) != nil {
		return result, ErrGUIIssuer
	}
	work, err := store.Claim(ctx)
	if err != nil {
		return result, ErrGUIIssuer
	}
	if work == nil {
		return GUIIssuerResult{State: "idle"}, nil
	}
	coordinator := &guiissuer.Coordinator{Store: store, Account: account, Publisher: checkedGUIPublisher{publisher: publisher, timer: policy.CleanupTimer}, Roots: roots}
	for result.Steps < 16 {
		if guiCleanupReady(ctx, publisher, policy.CleanupTimer) != nil {
			return result, ErrGUIIssuer
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 110*time.Second {
			if store.Release(ctx, *work, "waiting") != nil {
				return result, ErrGUIIssuer
			}
			result.State = "waiting"
			return result, nil
		}
		step, err := coordinator.Step(ctx, *work)
		if err != nil {
			return result, ErrGUIIssuer
		}
		result.Steps++
		result.State = step.State
		work = &step.Work
		if step.State != "progressed" {
			return result, nil
		}
	}
	if store.Release(ctx, *work, "waiting") != nil {
		return result, ErrGUIIssuer
	}
	result.State = "waiting"
	return result, nil
}
