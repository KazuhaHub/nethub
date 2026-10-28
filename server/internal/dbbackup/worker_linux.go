package dbbackup

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const workerLockName = ".nethub-backup-runtime.lock"
const workerStateName = "worker-health.json"

// AcquireRuntime excludes another worker using this runtime directory. The
// descriptor is close-on-exec, so child tools cannot retain it after worker death.
func AcquireRuntime(directory string) (io.Closer, error) {
	if !privateDirectory(directory) {
		return nil, ErrUnavailable
	}
	file, err := openWorkerLock(directory, true)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if err == unix.EWOULDBLOCK {
			return nil, ErrBusy
		}
		return nil, ErrUnavailable
	}
	return file, nil
}

func openWorkerLock(directory string, create bool) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if create {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Open(filepath.Join(directory, workerLockName), flags, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), "backup runtime lock")
	info, err := file.Stat()
	if err != nil || !privateFile(info) {
		file.Close()
		return nil, ErrUnavailable
	}
	return file, nil
}

func runtimeActive(directory string) bool {
	file, err := openWorkerLock(directory, false)
	if err != nil {
		return false
	}
	defer file.Close()
	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	return err == unix.EWOULDBLOCK
}

// WriteWorkerState atomically publishes non-secret phase metadata in private
// volatile storage. Callers must hold the runtime lock for their worker lifetime.
func WriteWorkerState(directory string, state WorkerState) error {
	if !privateDirectory(directory) || !validWorkerState(state) {
		return ErrIntegrity
	}
	state.AttemptStartedAt = state.AttemptStartedAt.UTC()
	state.AttemptDeadline = state.AttemptDeadline.UTC()
	state.LastSuccessfulCycleAt = state.LastSuccessfulCycleAt.UTC()
	root, err := os.OpenRoot(directory)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Close()
	suffix, err := nonce()
	if err != nil {
		return err
	}
	name := ".worker-health-" + suffix
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Remove(name)
	raw, err := json.Marshal(state)
	if err == nil {
		_, err = file.Write(append(raw, '\n'))
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil || root.Rename(name, workerStateName) != nil {
		return ErrUnavailable
	}
	return nil
}

func readWorkerState(directory string) (WorkerState, error) {
	var state WorkerState
	root, err := os.OpenRoot(directory)
	if err != nil {
		return state, ErrUnavailable
	}
	defer root.Close()
	info, err := root.Lstat(workerStateName)
	if err != nil || !privateFile(info) || info.Size() > 8192 {
		return state, ErrIntegrity
	}
	file, err := root.Open(workerStateName)
	if err != nil {
		return state, ErrUnavailable
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 8193))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil {
		return state, ErrIntegrity
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || !validWorkerState(state) {
		return state, ErrIntegrity
	}
	return state, nil
}

// CheckWorkerHealth requires a live runtime lock, a completed healthy cycle and
// recent private archive metadata. Full hashing belongs to the successful daily
// cycle and deep doctor check; an old archive cannot hide a failed worker phase.
func CheckWorkerHealth(ctx context.Context, directory, runtimeDirectory string, maxAge time.Duration) error {
	if ctx.Err() != nil || !privateDirectory(directory) || !privateDirectory(runtimeDirectory) || maxAge < time.Hour || maxAge > 7*24*time.Hour {
		return ErrUnavailable
	}
	if !runtimeActive(runtimeDirectory) {
		return ErrLastAttempt
	}
	state, err := readWorkerState(runtimeDirectory)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if state.AttemptStartedAt.After(now.Add(5*time.Minute)) || state.LastSuccessfulCycleAt.After(now.Add(5*time.Minute)) {
		return ErrIntegrity
	}
	if state.Outcome == "starting" || state.Outcome == "failed" || state.Outcome == "running" && now.After(state.AttemptDeadline.Add(time.Minute)) {
		return ErrLastAttempt
	}
	if state.LastSuccessfulCycleAt.IsZero() || now.Sub(state.LastSuccessfulCycleAt) > maxAge {
		return ErrStale
	}
	_, err = VerifyMetadata(ctx, directory, state.DeploymentFingerprint, maxAge)
	if err != nil {
		return err
	}
	after, err := readWorkerState(runtimeDirectory)
	if err != nil {
		return err
	}
	if !runtimeActive(runtimeDirectory) || state != after {
		return ErrBusy
	}
	return nil
}
