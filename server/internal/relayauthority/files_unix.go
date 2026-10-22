//go:build !windows

package relayauthority

import (
	"os"
	"syscall"
)

func owned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && (info.IsDir() || stat.Nlink == 1)
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return ErrCandidate
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrCandidate
	}
	return nil
}
