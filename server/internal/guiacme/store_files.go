package guiacme

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
)

func accountProtected(path string, directory bool) error {
	info, err := os.Lstat(path)
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	if err != nil || info.IsDir() != directory || info.Mode()&os.ModeSymlink != 0 || !directory && !info.Mode().IsRegular() || !accountOwned(info) || runtime.GOOS != "windows" && info.Mode().Perm() != mode {
		return ErrState
	}
	return nil
}

func (s *AccountStore) lease(create bool) (*os.File, error) {
	if s.checkParent() != nil || accountProtected(s.directory, true) != nil {
		return nil, ErrState
	}
	path := s.path("account.lock")
	var file *os.File
	var err error
	if create {
		file, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			if file.Chmod(0600) != nil || file.Sync() != nil || accountSync(s.directory) != nil {
				file.Close()
				return nil, ErrState
			}
		} else if !os.IsExist(err) {
			return nil, ErrState
		}
	}
	if file == nil {
		if accountProtected(path, false) != nil {
			return nil, ErrState
		}
		file, err = os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, ErrState
		}
	}
	info, err := file.Stat()
	named, nameError := os.Lstat(path)
	if err != nil || nameError != nil || !os.SameFile(info, named) || info.Size() != 0 || accountProtected(path, false) != nil {
		file.Close()
		return nil, ErrState
	}
	if err := accountLock(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func accountRelease(file *os.File) { accountUnlock(file); _ = file.Close() }

func accountRead(path string) ([]byte, error) {
	if accountProtected(path, false) != nil {
		return nil, ErrState
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrState
	}
	defer file.Close()
	info, err := file.Stat()
	named, nameError := os.Lstat(path)
	if err != nil || nameError != nil || !os.SameFile(info, named) || info.Size() < 1 || info.Size() > accountStateLimit {
		return nil, ErrState
	}
	data, err := io.ReadAll(io.LimitReader(file, accountStateLimit+1))
	if err != nil || len(data) > accountStateLimit {
		return nil, ErrState
	}
	return data, nil
}

func accountWrite(path string, data []byte) error {
	if _, err := os.Lstat(path); err == nil {
		if accountProtected(path, false) != nil {
			return ErrState
		}
	} else if !os.IsNotExist(err) {
		return ErrState
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".account-*")
	if err != nil {
		return ErrState
	}
	name := file.Name()
	defer os.Remove(name)
	_, err = file.Write(data)
	if err == nil {
		err = file.Chmod(0600)
	}
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil || closed != nil || os.Rename(name, path) != nil || accountSync(filepath.Dir(path)) != nil {
		return ErrState
	}
	return nil
}
