// Package hostlease serializes cooperating operations on a protected host path.
package hostlease

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var ErrBusy = errors.New("protected host operation already running")
var ErrLease = errors.New("protected host operation lease unavailable")

type Lease struct {
	file *os.File
	once sync.Once
}

func valid(info os.FileInfo, directory bool) bool {
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	return info.IsDir() == directory && (directory || info.Mode().IsRegular() && info.Size() == 0) &&
		info.Mode()&os.ModeSymlink == 0 && owned(info) && (runtime.GOOS == "windows" || info.Mode().Perm() == mode)
}

// Acquire never unlinks or replaces the inode. A process exit releases the OS
// lock; the empty persistent file is not itself evidence of a running operation.
func Acquire(path string) (*Lease, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrLease
	}
	parent := filepath.Dir(path)
	canonical, err := filepath.EvalSymlinks(parent)
	info, statErr := os.Lstat(parent)
	if err != nil || canonical != parent || statErr != nil || !valid(info, true) {
		return nil, ErrLease
	}
	var before os.FileInfo
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	created := err == nil
	if os.IsExist(err) {
		before, err = os.Lstat(path)
		if err != nil || !valid(before, false) {
			return nil, ErrLease
		}
		file, err = os.OpenFile(path, os.O_RDWR, 0)
	}
	if err != nil {
		return nil, ErrLease
	}
	ok := false
	defer func() {
		if !ok {
			file.Close()
		}
	}()
	if created {
		if file.Chmod(0600) != nil || file.Sync() != nil || syncDirectory(parent) != nil {
			return nil, ErrLease
		}
	}
	opened, err := file.Stat()
	if err != nil || !valid(opened, false) || before != nil && !os.SameFile(before, opened) {
		return nil, ErrLease
	}
	if err := lock(file); err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil || !valid(current, false) || !os.SameFile(opened, current) {
		unlock(file)
		return nil, ErrLease
	}
	ok = true
	return &Lease{file: file}, nil
}

func (l *Lease) Close() {
	if l != nil {
		l.once.Do(func() { unlock(l.file); _ = l.file.Close() })
	}
}
