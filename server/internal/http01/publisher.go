// Package http01 publishes issuer-approved public validation files, never private keys.
package http01

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

var (
	ErrInput     = errors.New("invalid HTTP-01 publication")
	ErrState     = errors.New("invalid HTTP-01 publication state")
	ErrBusy      = errors.New("HTTP-01 publication already active")
	ErrRetired   = errors.New("HTTP-01 operation already retired")
	ErrCancelled = errors.New("HTTP-01 operation cancelled")
)

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var labelPattern = regexp.MustCompile(`^[a-z0-9]{8}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
var generationPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Config struct {
	PublicDirectory, StateDirectory, DeviceDomain string
	ExcludedHosts                                 []string
	Now                                           func() time.Time
}

// Publication contains public HTTP validation data. Its caller must independently
// authorize the current device, assigned hostname and signed CSR before publishing.
type Publication struct {
	Host             string    `json:"host"`
	Generation       string    `json:"generation"`
	Token            string    `json:"token"`
	KeyAuthorization string    `json:"key_authorization"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type operation struct {
	Version int    `json:"version"`
	Phase   string `json:"phase"`
	Publication
}

type active struct {
	Generation string `json:"generation"`
}

type namespace struct {
	Version       int    `json:"version"`
	Domain        string `json:"domain"`
	StateBinding  string `json:"state_binding"`
	PublicBinding string `json:"public_binding"`
	PolicyBinding string `json:"policy_binding"`
}

type Publisher struct {
	public, state, domain string
	excluded              map[string]bool
	now                   func() time.Time
}

func New(config Config) (*Publisher, error) {
	if len(config.DeviceDomain) > 244 || !domainPattern.MatchString(config.DeviceDomain) || len(config.ExcludedHosts) > 32 {
		return nil, ErrInput
	}
	if _, err := netip.ParseAddr(config.DeviceDomain); err == nil {
		return nil, ErrInput
	}
	for _, path := range []string{config.PublicDirectory, config.StateDirectory} {
		if len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
			return nil, ErrInput
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil || parent != filepath.Dir(path) {
			return nil, ErrState
		}
	}
	a, b := config.PublicDirectory, config.StateDirectory
	if a == b || within(a, b) || within(b, a) {
		return nil, ErrInput
	}
	p := &Publisher{public: a, state: b, domain: config.DeviceDomain, excluded: map[string]bool{}, now: config.Now}
	if p.now == nil {
		p.now = time.Now
	}
	for _, host := range config.ExcludedHosts {
		if len(host) > 253 || !domainPattern.MatchString(host) {
			return nil, ErrInput
		}
		p.excluded[host] = true
	}
	if ensureDirectory(p.public, 0755) != nil || ensureDirectory(p.state, 0700) != nil {
		return nil, ErrState
	}
	if err := p.bindNamespace(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Publisher) bindNamespace() error {
	path := filepath.Join(p.public, ".publisher-lease")
	if !missing(path) && protected(path, false, 0644) != nil {
		return ErrState
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return ErrState
	}
	defer f.Close()
	// Set the intended public mode only on a newly empty lease, without exposing data.
	if info, err := f.Stat(); err != nil || !owned(info) || info.Size() != 0 {
		return ErrState
	}
	if f.Chmod(0644) != nil || protected(path, false, 0644) != nil {
		return ErrState
	}
	if err := lockFile(f); err != nil {
		return err
	}
	defer unlockFile(f)
	hash := sha256.Sum256([]byte(p.state))
	publicHash := sha256.Sum256([]byte(p.public))
	var excluded []string
	for host := range p.excluded {
		excluded = append(excluded, host)
	}
	sort.Strings(excluded)
	policy := sha256.Sum256([]byte(strings.Join(excluded, "\x00")))
	want := namespace{Version: 1, Domain: p.domain, StateBinding: hex.EncodeToString(hash[:]), PublicBinding: hex.EncodeToString(publicHash[:]), PolicyBinding: hex.EncodeToString(policy[:])}
	private := filepath.Join(p.state, "namespace.json")
	public := filepath.Join(p.public, ".publisher.json")
	privateExists, publicExists := !missing(private), !missing(public)
	if publicExists && !privateExists {
		return ErrState
	}
	if privateExists {
		var got namespace
		if readCanonical(private, &got) != nil || got != want {
			return ErrState
		}
	} else {
		entries, err := os.ReadDir(p.state)
		if err != nil || len(entries) != 0 {
			return ErrState
		}
	}
	if publicExists {
		var got namespace
		if readCanonicalMode(public, 0644, &got) != nil || got != want {
			return ErrState
		}
	} else {
		entries, err := os.ReadDir(p.public)
		if err != nil || len(entries) != 1 || entries[0].Name() != ".publisher-lease" {
			return ErrState
		}
	}
	if !privateExists && writeCanonical(private, want) != nil {
		return ErrState
	}
	if !publicExists {
		data, _ := json.MarshalIndent(want, "", "  ")
		if atomic(public, append(data, '\n'), 0644) != nil {
			return ErrState
		}
	}
	return nil
}

func within(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (p *Publisher) validHost(host string) bool {
	suffix := "." + p.domain
	return !p.excluded[host] && strings.HasSuffix(host, suffix) && labelPattern.MatchString(strings.TrimSuffix(host, suffix))
}

func (p *Publisher) validate(value Publication) bool {
	if !p.validHost(value.Host) || !generationPattern.MatchString(value.Generation) || !tokenPattern.MatchString(value.Token) || value.ExpiresAt.IsZero() || value.ExpiresAt.Location() != time.UTC {
		return false
	}
	prefix := value.Token + "."
	if !strings.HasPrefix(value.KeyAuthorization, prefix) {
		return false
	}
	thumb := strings.TrimPrefix(value.KeyAuthorization, prefix)
	if len(thumb) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(thumb)
	return err == nil && len(decoded) == 32
}

func cancelled(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return nil
}

func (p *Publisher) lease(ctx context.Context, host string) (string, *os.File, error) {
	if !p.validHost(host) {
		return "", nil, ErrInput
	}
	if err := cancelled(ctx); err != nil {
		return "", nil, err
	}
	if protected(p.state, true, 0700) != nil || protected(p.public, true, 0755) != nil {
		return "", nil, ErrState
	}
	dir := filepath.Join(p.state, host)
	if ensureDirectory(dir, 0700) != nil || ensureDirectory(filepath.Join(dir, "operations"), 0700) != nil {
		return "", nil, ErrState
	}
	path := filepath.Join(dir, "lease")
	if !missing(path) && protected(path, false, 0600) != nil {
		return "", nil, ErrState
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", nil, ErrState
	}
	if protected(path, false, 0600) != nil {
		f.Close()
		return "", nil, ErrState
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return "", nil, err
	}
	return dir, f, nil
}

func release(file *os.File) { unlockFile(file); _ = file.Close() }

func operationPath(dir, generation string) string {
	return filepath.Join(dir, "operations", generation+".json")
}

func (p *Publisher) loadOperation(dir, generation string) (operation, error) {
	var op operation
	if !generationPattern.MatchString(generation) || readCanonical(operationPath(dir, generation), &op) != nil || op.Version != 1 || op.Generation != generation || !p.validate(op.Publication) || filepath.Base(dir) != op.Host {
		return op, ErrState
	}
	switch op.Phase {
	case "publishing", "published", "removing", "removed":
	default:
		return op, ErrState
	}
	return op, nil
}

func loadActive(dir string) (string, error) {
	path := filepath.Join(dir, "active.json")
	if missing(path) {
		return "", nil
	}
	var value active
	if readCanonical(path, &value) != nil || !generationPattern.MatchString(value.Generation) {
		return "", ErrState
	}
	return value.Generation, nil
}

func saveOperation(dir string, op operation) error {
	return writeCanonical(operationPath(dir, op.Generation), op)
}

func (p *Publisher) publicPath(value Publication, create bool) (string, error) {
	base := p.public
	if protected(base, true, 0755) != nil {
		return "", ErrState
	}
	for _, name := range []string{value.Host, ".well-known", "acme-challenge"} {
		base = filepath.Join(base, name)
		if create {
			if ensureDirectory(base, 0755) != nil {
				return "", ErrState
			}
		} else {
			if missing(base) {
				return "", nil
			}
			if protected(base, true, 0755) != nil {
				return "", ErrState
			}
		}
	}
	return filepath.Join(base, value.Token), nil
}

func samePublic(path, expected string) error {
	if path == "" || missing(path) {
		return nil
	}
	data, err := readProtected(path, 0644, 256)
	if err != nil || string(data) != expected {
		return ErrState
	}
	return nil
}

// Publish is idempotent for immutable operation input. Only one unexpired
// generation may occupy a host; completed operations remain private tombstones.
func (p *Publisher) Publish(ctx context.Context, value Publication) error {
	value.ExpiresAt = value.ExpiresAt.UTC()
	now := p.now().UTC()
	if !p.validate(value) || !value.ExpiresAt.After(now) || value.ExpiresAt.After(now.Add(time.Hour)) {
		return ErrInput
	}
	dir, lease, err := p.lease(ctx, value.Host)
	if err != nil {
		return err
	}
	defer release(lease)
	op := operation{Version: 1, Phase: "publishing", Publication: value}
	knownOperation := !missing(operationPath(dir, value.Generation))
	if knownOperation {
		previous, err := p.loadOperation(dir, value.Generation)
		if err != nil {
			return err
		}
		if previous.Phase == "removed" || previous.Phase == "removing" {
			return ErrRetired
		}
		if previous.Publication != value {
			return ErrState
		}
		op = previous
	}
	current, err := loadActive(dir)
	if err != nil {
		return err
	}
	if current == value.Generation && !knownOperation {
		return ErrState
	}
	if current != "" && current != value.Generation {
		other, err := p.loadOperation(dir, current)
		if err != nil {
			return err
		}
		if other.Phase != "removed" && other.Phase != "removing" && other.ExpiresAt.After(now) {
			return ErrBusy
		}
		if err := p.removeLocked(dir, other); err != nil {
			return err
		}
		current = ""
	}
	path, err := p.publicPath(value, true)
	if err != nil {
		return err
	}
	if current == "" && missing(operationPath(dir, value.Generation)) && !missing(path) {
		return ErrState
	}
	if samePublic(path, value.KeyAuthorization) != nil {
		return ErrState
	}
	if cancelled(ctx) != nil {
		return ErrCancelled
	}
	if saveOperation(dir, op) != nil || writeCanonical(filepath.Join(dir, "active.json"), active{value.Generation}) != nil {
		return ErrState
	}
	if missing(path) && atomic(path, []byte(value.KeyAuthorization), 0644) != nil {
		return ErrState
	}
	op.Phase = "published"
	return saveOperation(dir, op)
}

func (p *Publisher) removeLocked(dir string, op operation) error {
	path, err := p.publicPath(op.Publication, false)
	if err != nil || samePublic(path, op.KeyAuthorization) != nil {
		return ErrState
	}
	op.Phase = "removing"
	if saveOperation(dir, op) != nil {
		return ErrState
	}
	if path != "" && !missing(path) {
		if os.Remove(path) != nil || syncDirectory(filepath.Dir(path)) != nil {
			return ErrState
		}
	}
	op.Phase = "removed"
	if saveOperation(dir, op) != nil {
		return ErrState
	}
	if os.Remove(filepath.Join(dir, "active.json")) != nil || syncDirectory(dir) != nil {
		return ErrState
	}
	return nil
}

// Remove never deletes another generation's publication, including a delayed
// cleanup left over from a completed operation.
func (p *Publisher) Remove(ctx context.Context, host, generation string) error {
	if !generationPattern.MatchString(generation) {
		return ErrInput
	}
	dir, lease, err := p.lease(ctx, host)
	if err != nil {
		return err
	}
	defer release(lease)
	current, err := loadActive(dir)
	if err != nil || current != generation {
		return err
	}
	op, err := p.loadOperation(dir, current)
	if err != nil {
		return err
	}
	return p.removeLocked(dir, op)
}

// CleanupExpired is called by the issuer's recovery scan. Static HTTP serving
// does not itself enforce this deadline; callers must schedule that scan.
func (p *Publisher) CleanupExpired(ctx context.Context, host string) error {
	_, err := p.cleanupExpired(ctx, host)
	return err
}

func (p *Publisher) cleanupExpired(ctx context.Context, host string) (bool, error) {
	dir, lease, err := p.lease(ctx, host)
	if err != nil {
		return false, err
	}
	defer release(lease)
	current, err := loadActive(dir)
	if err != nil || current == "" {
		return false, err
	}
	op, err := p.loadOperation(dir, current)
	if err != nil {
		return false, err
	}
	if op.Phase == "removing" || op.Phase == "removed" || !op.ExpiresAt.After(p.now().UTC()) {
		if err := p.removeLocked(dir, op); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func missing(path string) bool { _, err := os.Lstat(path); return os.IsNotExist(err) }
func ensureDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil {
		if !os.IsExist(err) {
			return ErrState
		}
	} else {
		if os.Chmod(path, mode) != nil || syncDirectory(path) != nil || syncDirectory(filepath.Dir(path)) != nil {
			return ErrState
		}
	}
	return protected(path, true, mode)
}
func protected(path string, directory bool, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || info.IsDir() != directory || info.Mode()&os.ModeSymlink != 0 || !directory && !info.Mode().IsRegular() || !owned(info) || runtime.GOOS != "windows" && info.Mode().Perm() != mode {
		return ErrState
	}
	return nil
}
func readProtected(path string, mode os.FileMode, limit int64) ([]byte, error) {
	if protected(path, false, mode) != nil {
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
func readCanonical(path string, target any) error {
	return readCanonicalMode(path, 0600, target)
}
func readCanonicalMode(path string, mode os.FileMode, target any) error {
	data, err := readProtected(path, mode, 2048)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrState
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrState
	}
	canonical, err := json.MarshalIndent(target, "", "  ")
	if err != nil || !bytes.Equal(data, append(canonical, '\n')) {
		return ErrState
	}
	return nil
}
func writeCanonical(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil || len(data) > 2047 {
		return ErrState
	}
	return atomic(path, append(data, '\n'), 0600)
}
func atomic(path string, data []byte, mode os.FileMode) error {
	if !missing(path) && protected(path, false, mode) != nil {
		return ErrState
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".publication-*")
	if err != nil {
		return ErrState
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil || closed != nil || os.Rename(name, path) != nil || syncDirectory(filepath.Dir(path)) != nil {
		return ErrState
	}
	return nil
}
