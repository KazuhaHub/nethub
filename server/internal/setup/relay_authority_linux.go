package setup

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"github.com/KazuhaHub/nethub/server/internal/relaycert"
)

// RunRelayAuthority prepares independent offline material. It never publishes
// trust, replaces active authority, updates a manifest or restarts a service.
func RunRelayAuthority(ctx context.Context, o RelayAuthorityOptions) (RelayAuthorityResult, error) {
	var result RelayAuthorityResult
	if ctx.Err() != nil || os.Geteuid() != 0 || !validRelayAuthorityOptions(o) {
		return result, ErrRelayAuthority
	}
	directory, err := filepath.Abs(o.Directory)
	if err != nil {
		return result, ErrRelayAuthority
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory || CheckAuthority(directory) != nil {
		return result, ErrRelayAuthority
	}
	manifest, err := Load(directory)
	if err != nil {
		return result, ErrRelayAuthority
	}
	for _, path := range []string{o.CandidateDirectory, o.BackupDirectory} {
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || pathsOverlap(directory, path) || pathsOverlap(manifest.BackupDirectory, path) {
			return result, ErrRelayAuthority
		}
		parent := filepath.Dir(path)
		actual, err := filepath.EvalSymlinks(parent)
		info, statErr := os.Lstat(parent)
		if err != nil || actual != parent || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || ownerUID(parent) != 0 {
			return result, ErrRelayAuthority
		}
	}
	ca, err := rootGUIFile(filepath.Join(directory, "secrets/issuer/ca.pem"), 32768, true)
	if err != nil {
		return result, ErrRelayAuthority
	}
	key, err := rootGUIFile(filepath.Join(directory, "secrets/issuer/ca-key.pem"), 32768, true)
	if err != nil {
		return result, ErrRelayAuthority
	}
	previous, err := relaycert.AuthorityIdentity(ca, key)
	if err != nil {
		return result, ErrRelayAuthority
	}
	var candidate relayauthority.Candidate
	now := time.Now()
	if o.Action == "prepare" {
		if previous != o.ExpectedRoot {
			return result, ErrRelayAuthority
		}
		candidate, err = relayauthority.Prepare(o.CandidateDirectory, manifest.Config.ConsoleHost, ca, key, now)
	} else {
		candidate, err = relayauthority.Load(o.CandidateDirectory, now)
	}
	if err != nil || candidate.Metadata.Previous != previous || candidate.Metadata.ServerName != manifest.Config.ConsoleHost {
		return result, ErrRelayAuthority
	}
	switch o.Action {
	case "backup":
		err = relayauthority.Backup(o.CandidateDirectory, o.BackupDirectory, now)
	case "verify-backup":
		err = relayauthority.VerifyBackup(o.CandidateDirectory, o.BackupDirectory, now)
	}
	if err != nil || ctx.Err() != nil {
		return result, ErrRelayAuthority
	}
	return RelayAuthorityResult{State: "prepared", Candidate: candidate.Metadata, BackupVerified: o.Action == "backup" || o.Action == "verify-backup"}, nil
}
