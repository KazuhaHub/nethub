package relaymaint

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

var ErrState = errors.New("invalid relay maintenance state")
var ErrBusy = errors.New("relay maintenance already running")
var generationName = regexp.MustCompile(`^[0-9a-f]{64}$`)

type store struct {
	root  string
	lease *os.File
}

func protected(path string, directory bool) error {
	info, err := os.Lstat(path)
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	if err != nil || info.IsDir() != directory || !directory && !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || !owned(info) || runtime.GOOS != "windows" && info.Mode().Perm() != mode {
		return ErrState
	}
	return nil
}

func openStore(root string) (*store, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(root))
	if err != nil || parent != filepath.Clean(filepath.Dir(root)) || protected(parent, true) != nil {
		return nil, ErrState
	}
	if err := os.Mkdir(root, 0700); err != nil {
		if !os.IsExist(err) {
			return nil, ErrState
		}
	} else if syncDirectory(parent) != nil {
		return nil, ErrState
	}
	if protected(root, true) != nil {
		return nil, ErrState
	}
	path := filepath.Join(root, "lease")
	if _, err := os.Lstat(path); err == nil && protected(path, false) != nil {
		return nil, ErrState
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrState
	}
	if protected(path, false) != nil {
		f.Close()
		return nil, ErrState
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, err
	}
	return &store{root: root, lease: f}, nil
}

func (s *store) close() { unlockFile(s.lease); _ = s.lease.Close() }

func readProtected(path string, limit int64) ([]byte, error) {
	if protected(filepath.Dir(path), true) != nil || protected(path, false) != nil {
		return nil, ErrState
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrState
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		return nil, ErrState
	}
	return data, nil
}

func replacePrivate(path string, data []byte) error {
	if protected(filepath.Dir(path), true) != nil {
		return ErrState
	}
	if _, err := os.Lstat(path); err == nil && protected(path, false) != nil {
		return ErrState
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return ErrState
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrState
	}
	if os.Rename(name, path) != nil || syncDirectory(filepath.Dir(path)) != nil {
		return ErrState
	}
	return nil
}

func (s *store) load() (State, error) {
	path := filepath.Join(s.root, "state.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return State{Version: 1, Phase: "idle"}, nil
	}
	raw, err := readProtected(path, 16384)
	if err != nil {
		return State{}, ErrState
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state State
	if decoder.Decode(&state) != nil || state.validate() != nil {
		return State{}, ErrState
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return State{}, ErrState
	}
	canonical, err := json.MarshalIndent(state, "", "  ")
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return State{}, ErrState
	}
	return state, nil
}

func (s *store) save(state State) error {
	if state.validate() != nil {
		return ErrState
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil || len(data) > 16384 {
		return ErrState
	}
	return replacePrivate(filepath.Join(s.root, "state.json"), append(data, '\n'))
}

func materialID(cert, key []byte) (string, error) {
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil || len(pair.Certificate) != 1 {
		return "", ErrState
	}
	hash := sha256.Sum256(pair.Certificate[0])
	return hex.EncodeToString(hash[:]), nil
}

func (s *store) generation(id string) ([]byte, []byte, error) {
	if !generationName.MatchString(id) {
		return nil, nil, ErrState
	}
	cert, key, err := s.pair(id)
	if err != nil {
		return nil, nil, err
	}
	actual, err := materialID(cert, key)
	if err != nil || actual != id {
		return nil, nil, ErrState
	}
	return cert, key, nil
}

func (s *store) pair(name string) ([]byte, []byte, error) {
	if name != "pending" && !generationName.MatchString(name) {
		return nil, nil, ErrState
	}
	dir := filepath.Join(s.root, name)
	cert, err := readProtected(filepath.Join(dir, "cert.pem"), 32768)
	if err != nil {
		return nil, nil, ErrState
	}
	key, err := readProtected(filepath.Join(dir, "key.pem"), 32768)
	if err != nil {
		return nil, nil, ErrState
	}
	if _, err := materialID(cert, key); err != nil {
		return nil, nil, ErrState
	}
	return cert, key, nil
}

func (s *store) put(cert, key []byte) (string, error) {
	id, err := materialID(cert, key)
	if err != nil {
		return "", err
	}
	if err := s.putPair(id, cert, key); err != nil {
		return "", err
	}
	return id, nil
}

func (s *store) putPair(name string, cert, key []byte) error {
	if name != "pending" && !generationName.MatchString(name) {
		return ErrState
	}
	dest := filepath.Join(s.root, name)
	if _, err := os.Lstat(dest); err == nil {
		a, b, err := s.pair(name)
		if err != nil || !bytes.Equal(a, cert) || !bytes.Equal(b, key) {
			return ErrState
		}
		return nil
	}
	temp, err := os.MkdirTemp(s.root, ".generation-*")
	if err != nil {
		return ErrState
	}
	defer func() {
		_ = os.Remove(filepath.Join(temp, "cert.pem"))
		_ = os.Remove(filepath.Join(temp, "key.pem"))
		_ = os.Remove(temp)
	}()
	for name, data := range map[string][]byte{"cert.pem": cert, "key.pem": key} {
		if replacePrivate(filepath.Join(temp, name), data) != nil {
			return ErrState
		}
	}
	if syncDirectory(temp) != nil || os.Rename(temp, dest) != nil || syncDirectory(s.root) != nil {
		return ErrState
	}
	return nil
}

func missing(path string) bool { _, err := os.Lstat(path); return os.IsNotExist(err) }

func removePending(s *store) error {
	source := filepath.Join(s.root, "pending")
	if missing(source) {
		return nil
	}
	if protected(source, true) != nil {
		return ErrState
	}
	retired, err := os.MkdirTemp(s.root, ".retired-*")
	if err != nil {
		return ErrState
	}
	if os.Remove(retired) != nil || os.Rename(source, retired) != nil || syncDirectory(s.root) != nil {
		return ErrState
	}
	// Retirement is durable before best-effort deletion of these exact files.
	// A crash cannot leave a half-deleted active pending generation.
	_ = os.Remove(filepath.Join(retired, "cert.pem"))
	_ = os.Remove(filepath.Join(retired, "key.pem"))
	_ = os.Remove(retired)
	return nil
}
