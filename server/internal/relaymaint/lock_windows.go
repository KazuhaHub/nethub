//go:build windows

package relaymaint

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Windows support exercises the journal in local tests. The host command and
// deployment durability guarantees are restricted to Linux.
func lockFile(file *os.File) error {
	err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrBusy
	}
	if err != nil {
		return ErrState
	}
	return nil
}
func unlockFile(file *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}
func owned(os.FileInfo) bool     { return true }
func syncDirectory(string) error { return nil }
