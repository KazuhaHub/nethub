package http01

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
)

type FileConfig struct {
	Version         int      `json:"version"`
	PublicDirectory string   `json:"public_directory"`
	StateDirectory  string   `json:"state_directory"`
	DeviceDomain    string   `json:"device_domain"`
	ExcludedHosts   []string `json:"excluded_hosts"`
}

// MatchesPolicy compares cleanup policy with independent deployment identity.
// Additional exclusions can restrict publication but cannot widen it.
func (p *Publisher) MatchesPolicy(domain string, protectedHosts []string) bool {
	if p == nil || p.domain != domain {
		return false
	}
	for _, host := range protectedHosts {
		if !p.excluded[host] {
			return false
		}
	}
	return true
}

// OpenExistingFile loads protected publisher policy without initializing or
// repairing a missing namespace. Cleanup needs no account, database or signer.
func OpenExistingFile(path string) (*Publisher, error) {
	if len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInput
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, ErrState
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || !owned(parent) || runtime.GOOS != "windows" && parent.Mode().Perm()&0022 != 0 {
		return nil, ErrState
	}
	data, err := readProtected(path, 0600, 20000)
	if err != nil {
		return nil, ErrState
	}
	fields, err := boundedjson.Object(bytes.NewReader(data))
	if err != nil || len(fields) != 5 {
		return nil, ErrInput
	}
	for _, name := range []string{"version", "public_directory", "state_directory", "device_domain", "excluded_hosts"} {
		if _, ok := fields[name]; !ok {
			return nil, ErrInput
		}
	}
	var config FileConfig
	if json.Unmarshal(data, &config) != nil || config.Version != 1 || config.ExcludedHosts == nil {
		return nil, ErrInput
	}
	for _, path := range []string{config.PublicDirectory, config.StateDirectory} {
		if len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, ErrInput
		}
	}
	if protected(config.PublicDirectory, true, 0755) != nil || protected(config.StateDirectory, true, 0700) != nil || protected(filepath.Join(config.PublicDirectory, ".publisher.json"), false, 0644) != nil || protected(filepath.Join(config.PublicDirectory, ".publisher-lease"), false, 0644) != nil || protected(filepath.Join(config.StateDirectory, "namespace.json"), false, 0600) != nil {
		return nil, ErrState
	}
	return New(Config{PublicDirectory: config.PublicDirectory, StateDirectory: config.StateDirectory, DeviceDomain: config.DeviceDomain, ExcludedHosts: config.ExcludedHosts})
}
