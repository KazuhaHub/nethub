//go:build !windows

package relaymaint

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func lockFile(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return ErrBusy
	}
	if err != nil {
		return ErrState
	}
	return nil
}
func unlockFile(file *os.File) { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN) }
func owned(info os.FileInfo) bool {
	value, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(value.Uid) == os.Geteuid() && (info.IsDir() || value.Nlink == 1)
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
