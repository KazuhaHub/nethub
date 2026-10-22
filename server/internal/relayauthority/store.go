// Package relayauthority preserves an offline successor before any active change.
package relayauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
	"github.com/KazuhaHub/nethub/server/internal/relaycert"
)

var ErrCandidate = errors.New("relay authority candidate requires protected independent material")
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var names = []string{"ca.pem", "ca-key.pem", "relay-cert.pem", "relay-key.pem"}

type Metadata struct {
	Version    int               `json:"version"`
	ServerName string            `json:"server_name"`
	Previous   string            `json:"previous_root_fingerprint"`
	Next       string            `json:"next_root_fingerprint"`
	PreparedAt time.Time         `json:"prepared_at"`
	Files      map[string]string `json:"files"`
}

type Candidate struct {
	Metadata Metadata           `json:"metadata"`
	Material relaycert.Material `json:"-"`
}

func digest(raw []byte) string { d := sha256.Sum256(raw); return hex.EncodeToString(d[:]) }

func protected(path string, directory bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	if err != nil || info.IsDir() != directory || !directory && !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || !owned(info) || runtime.GOOS != "windows" && info.Mode().Perm() != mode {
		return nil, ErrCandidate
	}
	return info, nil
}

func canonical(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == path {
		return false
	}
	actual, err := filepath.EvalSymlinks(path)
	return err == nil && actual == path
}

func read(path string, maximum int64) ([]byte, error) {
	if !canonical(path) {
		return nil, ErrCandidate
	}
	before, err := protected(path, false)
	if err != nil || before.Size() < 1 || before.Size() > maximum {
		return nil, ErrCandidate
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrCandidate
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, ErrCandidate
	}
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	after, afterErr := f.Stat()
	if err != nil || afterErr != nil || int64(len(raw)) != before.Size() || !os.SameFile(before, after) ||
		after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, ErrCandidate
	}
	return raw, nil
}

func materialFiles(m relaycert.Material) map[string][]byte {
	return map[string][]byte{"ca.pem": m.CA, "ca-key.pem": m.CAKey, "relay-cert.pem": m.Certificate, "relay-key.pem": m.Key}
}

func validate(c Candidate, now time.Time) error {
	m := c.Metadata
	if m.Version != 1 || !digestPattern.MatchString(m.Previous) || !digestPattern.MatchString(m.Next) || m.Previous == m.Next ||
		m.PreparedAt.IsZero() || m.PreparedAt.After(now.Add(5*time.Second)) || len(m.Files) != 4 {
		return ErrCandidate
	}
	id, err := relaycert.AuthorityIdentity(c.Material.CA, c.Material.CAKey)
	if err != nil || id != m.Next || relaycert.Check(c.Material.CA, c.Material.Certificate, c.Material.Key, m.ServerName, now) != nil {
		return ErrCandidate
	}
	for name, raw := range materialFiles(c.Material) {
		if m.Files[name] != digest(raw) {
			return ErrCandidate
		}
	}
	return nil
}

// Prepare generates only an offline successor. Existing and partial outputs are
// never replaced; an interrupted directory needs explicit operator inspection.
func Prepare(directory, name string, oldCA, oldKey []byte, now time.Time) (Candidate, error) {
	var result Candidate
	previous, err := relaycert.AuthorityIdentity(oldCA, oldKey)
	if err != nil || now.IsZero() {
		return result, ErrCandidate
	}
	material, err := relaycert.Create(name, now)
	if err != nil {
		return result, ErrCandidate
	}
	next, err := relaycert.AuthorityIdentity(material.CA, material.CAKey)
	if err != nil {
		return result, ErrCandidate
	}
	result = Candidate{Metadata: Metadata{Version: 1, ServerName: name, Previous: previous, Next: next, PreparedAt: now.UTC(), Files: map[string]string{}}, Material: material}
	for n, raw := range materialFiles(material) {
		result.Metadata.Files[n] = digest(raw)
	}
	if validate(result, now) != nil || publish(directory, result) != nil {
		return Candidate{}, ErrCandidate
	}
	return result, nil
}

func publish(directory string, c Candidate) error {
	parent := filepath.Dir(directory)
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !canonical(parent) {
		return ErrCandidate
	}
	if _, err := protected(parent, true); err != nil {
		return ErrCandidate
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return ErrCandidate
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	write := func(name string, raw []byte) error {
		f, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return ErrCandidate
		}
		if err = f.Chmod(0600); err == nil {
			_, err = f.Write(raw)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return ErrCandidate
		}
		return nil
	}
	// Metadata is the completion record and is written only after all key material.
	for _, name := range names {
		if err := write(name, materialFiles(c.Material)[name]); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(c.Metadata)
	if err != nil {
		return ErrCandidate
	}
	if err = write("candidate.json", append(raw, '\n')); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func Load(directory string, now time.Time) (Candidate, error) {
	var c Candidate
	if !canonical(directory) {
		return c, ErrCandidate
	}
	if _, err := protected(directory, true); err != nil {
		return c, ErrCandidate
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 5 {
		return c, ErrCandidate
	}
	raw, err := read(filepath.Join(directory, "candidate.json"), 8192)
	if err != nil {
		return c, ErrCandidate
	}
	fields, err := boundedjson.Object(bytes.NewReader(raw))
	if err != nil || len(fields) != 6 {
		return c, ErrCandidate
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c.Metadata) != nil {
		return Candidate{}, ErrCandidate
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return Candidate{}, ErrCandidate
	}
	canonicalJSON, err := json.Marshal(c.Metadata)
	if err != nil || !bytes.Equal(raw, append(canonicalJSON, '\n')) {
		return Candidate{}, ErrCandidate
	}
	files := map[string][]byte{}
	for _, name := range names {
		files[name], err = read(filepath.Join(directory, name), 32768)
		if err != nil {
			return Candidate{}, ErrCandidate
		}
	}
	c.Material = relaycert.Material{CA: files["ca.pem"], CAKey: files["ca-key.pem"], Certificate: files["relay-cert.pem"], Key: files["relay-key.pem"]}
	if validate(c, now) != nil {
		return Candidate{}, ErrCandidate
	}
	return c, nil
}

func overlap(a, b string) bool {
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// Backup preserves exact bytes in a new independent directory. It does not
// acknowledge operator custody or make a candidate eligible for activation.
func Backup(source, destination string, now time.Time) error {
	c, err := Load(source, now)
	if err != nil || overlap(source, destination) {
		return ErrCandidate
	}
	if publish(destination, c) != nil {
		return ErrCandidate
	}
	return VerifyBackup(source, destination, now)
}

func VerifyBackup(source, destination string, now time.Time) error {
	if overlap(source, destination) {
		return ErrCandidate
	}
	a, err := Load(source, now)
	if err != nil {
		return ErrCandidate
	}
	b, err := Load(destination, now)
	if err != nil {
		return ErrCandidate
	}
	left, _ := json.Marshal(a.Metadata)
	right, _ := json.Marshal(b.Metadata)
	if !bytes.Equal(left, right) {
		return ErrCandidate
	}
	files := append(append([]string{}, names...), "candidate.json")
	for _, name := range files {
		ai, err := os.Stat(filepath.Join(source, name))
		if err != nil {
			return ErrCandidate
		}
		for _, other := range files {
			bi, err := os.Stat(filepath.Join(destination, other))
			if err != nil || os.SameFile(ai, bi) {
				return ErrCandidate
			}
		}
	}
	return nil
}
