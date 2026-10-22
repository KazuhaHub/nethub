package hostlease

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Windows checks local locking semantics; protected deployment operations run on Linux.
func owned(os.FileInfo) bool     { return true }
func syncDirectory(string) error { return nil }
func lock(f *os.File) error {
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrBusy
	}
	if err != nil {
		return ErrLease
	}
	return nil
}
func unlock(f *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &windows.Overlapped{})
}
