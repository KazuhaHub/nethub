package dbbackup

import (
	"os"
	"strings"
)

// CheckStorage validates the caller's private storage and password file before
// opening a database connection. Run independently rechecks them before use.
func CheckStorage(directory, runtimeDirectory, passwordFile string) error {
	if CheckArchiveAccess(directory, passwordFile) != nil || !privateDirectory(runtimeDirectory) {
		return ErrUnavailable
	}
	dataPath, runtimePath := directory+string(os.PathSeparator), runtimeDirectory+string(os.PathSeparator)
	if strings.HasPrefix(dataPath, runtimePath) || strings.HasPrefix(runtimePath, dataPath) {
		return ErrUnavailable
	}
	return nil
}

// CheckArchiveAccess validates private inputs before a deep doctor's database
// connection; checking an archive does not require an active worker runtime.
func CheckArchiveAccess(directory, passwordFile string) error {
	if !privateDirectory(directory) {
		return ErrUnavailable
	}
	_, err := password(passwordFile)
	return err
}
