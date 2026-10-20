//go:build linux

package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
	"github.com/KazuhaHub/nethub/server/internal/guiacme"
	"github.com/KazuhaHub/nethub/server/internal/http01"
)

// RunGUIAccount is an explicit root-host operation, never a timer or web action.
// It reuses the protected deployment identity and issuer policy without Docker,
// publisher initialization, account replacement or implied registration consent.
func RunGUIAccount(ctx context.Context, o GUIAccountOptions) (GUIAccountResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if os.Geteuid() != 0 || !validGUIAccountOptions(o) || ctx.Err() != nil {
		return GUIAccountResult{}, ErrGUIAccount
	}
	directory, err := filepath.Abs(o.Directory)
	if err != nil {
		return GUIAccountResult{}, ErrGUIAccount
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory || CheckAuthority(directory) != nil {
		return GUIAccountResult{}, ErrGUIAccount
	}
	manifest, err := Load(directory)
	if err != nil || validateIdentity(manifest.Config) != nil {
		return GUIAccountResult{}, ErrGUIAccount
	}
	data, err := rootGUIFile(o.ConfigFile, 32768, true)
	if err != nil {
		return GUIAccountResult{}, ErrGUIAccount
	}
	policy, err := decodeGUIIssuerPolicy(data)
	if err != nil {
		return GUIAccountResult{}, ErrGUIAccount
	}
	// Read policy only, without acquiring or mutating the publisher namespace.
	data, err = rootGUIFile(policy.HTTPPolicyFile, 20000, true)
	if err != nil {
		return GUIAccountResult{}, ErrGUIAccount
	}
	fields, err := boundedjson.Object(bytes.NewReader(data))
	if err != nil || len(fields) != 5 {
		return GUIAccountResult{}, ErrGUIAccount
	}
	for _, name := range []string{"version", "public_directory", "state_directory", "device_domain", "excluded_hosts"} {
		if _, ok := fields[name]; !ok {
			return GUIAccountResult{}, ErrGUIAccount
		}
	}
	var publication http01.FileConfig
	if json.Unmarshal(data, &publication) != nil || publication.Version != 1 || publication.ExcludedHosts == nil || publication.DeviceDomain != manifest.Config.DeviceDomain {
		return GUIAccountResult{}, ErrGUIAccount
	}
	for _, path := range []string{policy.AccountDirectory, o.BackupDirectory} {
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 {
			return GUIAccountResult{}, ErrGUIAccount
		}
		for _, root := range []string{directory, publication.PublicDirectory, publication.StateDirectory} {
			if !filepath.IsAbs(root) || filepath.Clean(root) != root || pathsOverlap(root, path) {
				return GUIAccountResult{}, ErrGUIAccount
			}
			resolved, err := filepath.EvalSymlinks(root)
			info, statErr := os.Lstat(root)
			if err != nil || resolved != root || statErr != nil || !info.IsDir() || ownerUID(root) != 0 || info.Mode().Perm()&0022 != 0 {
				return GUIAccountResult{}, ErrGUIAccount
			}
		}
	}
	roots, err := guiTrustRoots(policy.APIRootsFile)
	if err != nil {
		return GUIAccountResult{}, ErrGUIAccount
	}
	store, err := guiacme.NewAccountStore(policy.AccountDirectory, guiacme.Config{DirectoryURL: policy.DirectoryURL, ContactEmail: policy.ContactEmail, AdditionalOrigins: policy.AdditionalOrigins, Roots: roots})
	if err != nil {
		return GUIAccountResult{}, ErrGUIAccount
	}
	terms := ""
	if o.Action == "register" {
		data, err := rootGUIFile(o.TermsFile, 8192, true)
		if err != nil {
			return GUIAccountResult{}, ErrGUIAccount
		}
		terms, err = decodeGUIAccountConsent(data)
		if err != nil {
			return GUIAccountResult{}, ErrGUIAccount
		}
	}
	return runGUIAccountAction(ctx, store, o, terms)
}

func pathsOverlap(a, b string) bool {
	within := func(parent, child string) bool {
		r, err := filepath.Rel(parent, child)
		return err == nil && (r == "." || r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)))
	}
	return within(a, b) || within(b, a)
}
