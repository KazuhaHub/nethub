//go:build !windows

package setup

import (
	"os"
	"syscall"
)

func ownerUID(path string) int {
	info, err := os.Lstat(path)
	if err != nil {
		return -1
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}
