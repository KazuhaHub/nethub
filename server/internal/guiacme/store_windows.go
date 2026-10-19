//go:build windows

package guiacme

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Windows supports local state tests; production issuer durability needs Unix.
func accountLock(file *os.File) error {
	err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrBusy
	}
	if err != nil {
		return ErrState
	}
	return nil
}
func accountUnlock(file *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}
func accountOwned(os.FileInfo) bool      { return true }
func accountParentMode(os.FileInfo) bool { return true }
func accountSync(string) error           { return nil }
