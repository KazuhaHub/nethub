package dbbackup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const stateName = "last-run.json"

func privateDirectory(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	info, statErr := os.Lstat(path)
	if err != nil || resolved != path || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func privateFile(info os.FileInfo) bool {
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func nonce() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(raw[:]), nil
}

func readState(root *os.Root) (State, error) {
	var state State
	info, err := root.Lstat(stateName)
	if err != nil || !privateFile(info) || info.Size() > 8192 {
		return state, ErrIntegrity
	}
	file, err := root.Open(stateName)
	if err != nil {
		return state, ErrIntegrity
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 8193))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil {
		return state, ErrIntegrity
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || !validState(state) {
		return state, ErrIntegrity
	}
	return state, nil
}

func writeState(root *os.Root, state State) error {
	value, err := nonce()
	if err != nil {
		return err
	}
	name := ".state-" + value
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Remove(name)
	data, err := json.Marshal(state)
	if err == nil {
		_, err = file.Write(append(data, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil || root.Rename(name, stateName) != nil {
		return ErrUnavailable
	}
	directory, err := root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

func lock(directory string) (*os.File, error) {
	fd, err := unix.Open(filepath.Join(directory, ".nethub-backup.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), "backup lock")
	info, err := file.Stat()
	if err != nil || !privateFile(info) {
		file.Close()
		return nil, ErrUnavailable
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if err == unix.EWOULDBLOCK {
			return nil, ErrBusy
		}
		return nil, ErrUnavailable
	}
	return file, nil
}

func password(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !privateFile(info) || info.Size() > 4096 {
		return nil, ErrUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	value := strings.TrimSpace(string(raw))
	if err != nil || len(raw) > 4096 || len(value) < 32 || strings.ContainsAny(value, "\r\n\x00") {
		return nil, ErrUnavailable
	}
	return raw, nil
}

type archiveWriter struct {
	file         *os.File
	digest       hash.Hash
	count, limit int64
	prefix       []byte
}

func (w *archiveWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.limit-w.count {
		return 0, ErrDump
	}
	n, err := w.file.Write(data)
	if n > 0 {
		w.digest.Write(data[:n])
		w.count += int64(n)
		if len(w.prefix) < 5 {
			left := 5 - len(w.prefix)
			if left > n {
				left = n
			}
			w.prefix = append(w.prefix, data[:left]...)
		}
	}
	return n, err
}

func Run(ctx context.Context, config Config) (result Receipt, failure error) {
	if ctx.Err() != nil || !digestPattern.MatchString(config.DeploymentFingerprint) || config.Host == "" || len(config.Host) > 255 || strings.ContainsAny(config.Host, "/\\\r\n\x00 =") || !databasePattern.MatchString(config.Database) || config.Port == 0 || config.SSLMode != "verify-full" && config.SSLMode != "disable" || config.Timeout < time.Second || config.Timeout > 30*time.Minute || config.MaxBytes < 1024 || config.MaxBytes > 1<<40 || !privateDirectory(config.Directory) || !privateDirectory(config.RuntimeDirectory) {
		return result, ErrUnavailable
	}
	dataPath, runPath := config.Directory+string(os.PathSeparator), config.RuntimeDirectory+string(os.PathSeparator)
	if strings.HasPrefix(dataPath, runPath) || strings.HasPrefix(runPath, dataPath) {
		return result, ErrUnavailable
	}
	guard, err := lock(config.Directory)
	if err != nil {
		return result, err
	}
	defer guard.Close()
	root, err := os.OpenRoot(config.Directory)
	if err != nil {
		return result, ErrUnavailable
	}
	defer root.Close()
	rawPassword, err := password(config.PasswordFile)
	if err != nil {
		return result, err
	}
	started := time.Now().UTC()
	state := State{Version: 1, DeploymentFingerprint: config.DeploymentFingerprint, AttemptStartedAt: started, AttemptDeadline: started.Add(config.Timeout), Outcome: "running"}
	if _, err := root.Lstat(stateName); err == nil {
		previous, err := readState(root)
		if err != nil || previous.DeploymentFingerprint != state.DeploymentFingerprint {
			return result, ErrIntegrity
		}
		state.LatestSuccess = previous.LatestSuccess
	} else if !os.IsNotExist(err) {
		return result, ErrUnavailable
	}
	if writeState(root, state) != nil {
		return result, ErrUnavailable
	}
	previousSuccess := state.LatestSuccess
	defer func() {
		if failure != nil {
			state.Outcome = "failed"
			state.LatestSuccess = previousSuccess
			_ = writeState(root, state)
		}
	}()
	ctx, cancel := context.WithDeadline(ctx, state.AttemptDeadline)
	defer cancel()
	value, err := nonce()
	if err != nil {
		return result, ErrUnavailable
	}
	runtime, err := os.MkdirTemp(config.RuntimeDirectory, "nethub-backup-")
	if err != nil {
		return result, ErrUnavailable
	}
	passPath := filepath.Join(runtime, "pgpass")
	defer func() { os.Remove(passPath); os.Remove(runtime) }()
	escape := strings.NewReplacer(`\`, `\\`, `:`, `\:`)
	pass := escape.Replace(config.Host) + ":" + strconv.Itoa(int(config.Port)) + ":" + escape.Replace(config.Database) + ":nethub_backup:" + escape.Replace(strings.TrimSpace(string(rawPassword))) + "\n"
	if os.WriteFile(passPath, []byte(pass), 0600) != nil {
		return result, ErrUnavailable
	}
	binary := config.dumpBinary
	if binary == "" {
		binary = "/usr/local/bin/pg_dump"
	}
	versionCommand := exec.CommandContext(ctx, binary, "--version")
	versionCommand.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	var version bytes.Buffer
	versionCommand.Stdout = &limitedVersion{target: &version}
	versionCommand.Stderr = io.Discard
	versionCommand.WaitDelay = 2 * time.Second
	if versionCommand.Run() != nil {
		return result, ErrDump
	}
	match := dumpVersionPattern.FindStringSubmatch(version.String())
	if len(match) != 2 || !normalizedVersionPattern.MatchString(match[1]) {
		return result, ErrDump
	}
	name := "nethub-" + started.Format("20060102T150405Z") + "-" + value + ".dump"
	partial := ".partial-" + value
	file, err := root.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, ErrUnavailable
	}
	defer func() { file.Close(); root.Remove(partial) }()
	writer := &archiveWriter{file: file, digest: sha256.New(), limit: config.MaxBytes}
	command := exec.CommandContext(ctx, binary, "--format=custom", "--no-password")
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C", "LC_ALL=C", "PGHOST=" + config.Host, "PGPORT=" + strconv.Itoa(int(config.Port)), "PGDATABASE=" + config.Database, "PGUSER=nethub_backup", "PGSSLMODE=" + config.SSLMode, "PGPASSFILE=" + passPath}
	command.Stdout = writer
	command.Stderr = io.Discard
	command.WaitDelay = 2 * time.Second
	if command.Run() != nil || ctx.Err() != nil || string(writer.prefix) != "PGDMP" || writer.count < 5 {
		return result, ErrDump
	}
	if file.Sync() != nil || file.Close() != nil || root.Rename(partial, name) != nil {
		return result, ErrUnavailable
	}
	completedAt := time.Now().UTC()
	if ctx.Err() != nil || completedAt.After(state.AttemptDeadline) {
		return result, ErrDump
	}
	result = Receipt{Archive: name, SHA256: hex.EncodeToString(writer.digest.Sum(nil)), Bytes: writer.count, StartedAt: started, CompletedAt: completedAt, Role: "nethub_backup", DumpVersion: match[1]}
	state.Outcome = "succeeded"
	completed := result
	state.LatestSuccess = &completed
	if writeState(root, state) != nil {
		return Receipt{}, ErrUnavailable
	}
	return result, nil
}

type limitedVersion struct{ target *bytes.Buffer }

func (w *limitedVersion) Write(data []byte) (int, error) {
	if w.target.Len()+len(data) > 256 {
		return 0, ErrDump
	}
	return w.target.Write(data)
}

func Verify(ctx context.Context, directory, expectedFingerprint string, maxAge time.Duration) (Status, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !privateDirectory(directory) || !digestPattern.MatchString(expectedFingerprint) || maxAge < time.Hour || maxAge > 7*24*time.Hour {
		return Status{}, ErrUnavailable
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return Status{}, ErrUnavailable
	}
	defer root.Close()
	state, err := readState(root)
	if err != nil || state.DeploymentFingerprint != expectedFingerprint {
		return Status{}, ErrIntegrity
	}
	now := time.Now().UTC()
	if state.AttemptStartedAt.After(now.Add(5 * time.Minute)) {
		return Status{}, ErrIntegrity
	}
	if state.Outcome == "failed" || state.Outcome == "running" && now.After(state.AttemptDeadline.Add(time.Minute)) {
		return Status{}, ErrLastAttempt
	}
	if state.LatestSuccess == nil {
		return Status{}, ErrStale
	}
	receipt := *state.LatestSuccess
	if !validReceipt(receipt) || receipt.CompletedAt.After(now.Add(5*time.Minute)) {
		return Status{}, ErrIntegrity
	}
	if now.Sub(receipt.CompletedAt) > maxAge {
		return Status{}, ErrStale
	}
	info, err := root.Lstat(receipt.Archive)
	if err != nil || !privateFile(info) || info.Size() != receipt.Bytes {
		return Status{}, ErrIntegrity
	}
	file, err := root.Open(receipt.Archive)
	if err != nil {
		return Status{}, ErrIntegrity
	}
	defer file.Close()
	digest := sha256.New()
	buffer := make([]byte, 65536)
	var total int64
	var prefix []byte
	for {
		if ctx.Err() != nil {
			return Status{}, ErrUnavailable
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > receipt.Bytes {
				return Status{}, ErrIntegrity
			}
			digest.Write(buffer[:n])
			if len(prefix) < 5 {
				size := 5 - len(prefix)
				if size > n {
					size = n
				}
				prefix = append(prefix, buffer[:size]...)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return Status{}, ErrIntegrity
		}
	}
	if total != receipt.Bytes || string(prefix) != "PGDMP" || hex.EncodeToString(digest.Sum(nil)) != receipt.SHA256 {
		return Status{}, ErrIntegrity
	}
	return Status{Receipt: receipt, InProgress: state.Outcome == "running"}, nil
}
