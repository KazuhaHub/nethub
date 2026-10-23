package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/KazuhaHub/nethub/server/internal/http01"
)

var ErrHTTP01Initialization = errors.New("HTTP-01 namespace initialization unavailable")

// InitializeHTTP01 creates only an explicitly selected, deployment-bound
// namespace. Existing complete state is verified; partial state is retained.
func InitializeHTTP01(ctx context.Context, directory, policy string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || ctx.Err() != nil {
		return ErrHTTP01Initialization
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return ErrHTTP01Initialization
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory || CheckAuthority(directory) != nil {
		return ErrHTTP01Initialization
	}
	manifest, err := Load(directory)
	if err != nil || validateIdentity(manifest.Config) != nil {
		return ErrHTTP01Initialization
	}
	config, err := http01.ReadFileConfig(policy)
	if err != nil || config.DeviceDomain != manifest.Config.DeviceDomain || !slices.Contains(config.ExcludedHosts, manifest.Config.ConsoleHost) {
		return ErrHTTP01Initialization
	}
	exists := false
	for _, path := range []string{config.PublicDirectory, config.StateDirectory} {
		if path == directory || strings.HasPrefix(path, directory+string(os.PathSeparator)) || strings.HasPrefix(directory, path+string(os.PathSeparator)) {
			return ErrHTTP01Initialization
		}
		parent := filepath.Dir(path)
		resolved, resolveErr := filepath.EvalSymlinks(parent)
		info, statErr := os.Lstat(parent)
		if resolveErr != nil || resolved != parent || statErr != nil || !info.IsDir() || ownerUID(parent) != 0 || info.Mode().Perm()&0022 != 0 {
			return ErrHTTP01Initialization
		}
		if _, err := os.Lstat(path); err == nil {
			exists = true
		} else if !os.IsNotExist(err) {
			return ErrHTTP01Initialization
		}
	}
	if ctx.Err() != nil {
		return ErrHTTP01Initialization
	}
	if exists {
		if _, err := http01.OpenExistingFile(policy); err != nil {
			return ErrHTTP01Initialization
		}
		return nil
	}
	_, err = http01.New(http01.Config{PublicDirectory: config.PublicDirectory, StateDirectory: config.StateDirectory,
		DeviceDomain: config.DeviceDomain, ExcludedHosts: config.ExcludedHosts})
	if err != nil {
		return ErrHTTP01Initialization
	}
	return nil
}
