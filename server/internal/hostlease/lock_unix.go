//go:build !windows

package hostlease

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func owned(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && (info.IsDir() || s.Nlink == 1)
}
func lock(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return ErrBusy
	}
	if err != nil {
		return ErrLease
	}
	return nil
}
func unlock(f *os.File) { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return ErrLease
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrLease
	}
	return nil
}
