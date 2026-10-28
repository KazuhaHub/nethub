//go:build !linux

package dbbackup

func CheckStorage(string, string, string) error { return ErrUnavailable }
func CheckArchiveAccess(string, string) error   { return ErrUnavailable }
