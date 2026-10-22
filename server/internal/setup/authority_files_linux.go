package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

// RelayAuthorityService is the trusted host's bounded, identity-checked service
// adapter. Reload must reload authz bootstrap trust and frps, not just edit files.
// Observe must independently verify CA/name and return the actual served leaf.
// An expected/configured fingerprint is not an implementation of observation.
type RelayAuthorityService interface {
	Reload(context.Context, []byte) error
	Observe(context.Context, []byte) (string, error)
}

// RelayAuthoritySnapshotHost implements recoverable filesystem migration. The
// caller must use relayauthority.Transition with the real database fence and an
// independently checked service adapter. Methods require the shared relay lease
// already held by that coordinator; they must not be called as standalone writes.
type RelayAuthoritySnapshotHost struct {
	Options    RelayAuthoritySnapshotOptions
	Service    RelayAuthorityService
	checkpoint func(string)
}

var _ relayauthority.TransitionHost = (*RelayAuthoritySnapshotHost)(nil)

func (h *RelayAuthoritySnapshotHost) Snapshot(ctx context.Context, operation string, r relaytrust.SwitchRequest) (string, error) {
	if h == nil || h.Service == nil || r != h.Options.Request {
		return "", ErrRelayAuthority
	}
	return prepareAuthoritySnapshot(ctx, operation, h.Options)
}

func (h *RelayAuthoritySnapshotHost) snapshot(ctx context.Context, operation string, r relaytrust.SwitchRequest, expected string) (authoritySnapshot, error) {
	var s authoritySnapshot
	if h == nil || h.Service == nil || os.Geteuid() != 0 || ctx.Err() != nil || r != h.Options.Request || operation != filepath.Join(h.Options.Directory, "authority-transitions", r.ID) {
		return s, ErrRelayAuthority
	}
	actual, err := prepareAuthoritySnapshot(ctx, operation, h.Options)
	if err != nil || actual != expected {
		return s, ErrRelayAuthority
	}
	raw, err := authorityRead(filepath.Join(operation, "snapshot.json"), 0, 1048576)
	if err != nil || json.Unmarshal(raw, &s) != nil {
		return s, ErrRelayAuthority
	}
	return s, nil
}

func authorityReplace(path string, uid int, raw []byte) error {
	if _, err := authorityRead(path, uid, 32768); err != nil {
		return ErrRelayAuthority
	}
	parent := filepath.Dir(path)
	f, err := os.CreateTemp(parent, ".authority-*")
	if err != nil {
		return ErrRelayAuthority
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Chmod(0600); err == nil {
		err = f.Chown(uid, uid)
	}
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(temporary, path) != nil || authoritySyncDirectory(parent) != nil {
		return ErrRelayAuthority
	}
	return nil
}

func authoritySyncMaterial(path string, uid int) error {
	if _, err := authorityRead(path, uid, 32768); err != nil {
		return ErrRelayAuthority
	}
	before, err := os.Lstat(path)
	if err != nil {
		return ErrRelayAuthority
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return ErrRelayAuthority
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		f.Close()
		return ErrRelayAuthority
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil || closeErr != nil || authoritySyncDirectory(filepath.Dir(path)) != nil {
		return ErrRelayAuthority
	}
	return nil
}

func authorityTreeMatches(path string, s authoritySnapshot) (bool, bool, error) {
	entries, present, err := authorityTree(path)
	if err != nil {
		return false, present, err
	}
	return present && bytes.Equal(authorityJSON(entries), authorityJSON(s.Maintenance)), present, nil
}

// moveAuthorityMaintenance archives the original journal without deleting it.
// The two possible locations are rechecked on every retry. An unexpected or new
// journal is never silently removed to make a rollback appear successful.
func moveAuthorityMaintenance(directory, operation string, s authoritySnapshot, rollback bool) error {
	live := filepath.Join(directory, "secrets/issuer/maintenance")
	archive := filepath.Join(operation, "retained-maintenance")
	liveMatches, liveExists, err := authorityTreeMatches(live, s)
	if err != nil {
		return err
	}
	archiveMatches, archiveExists, err := authorityTreeMatches(archive, s)
	if err != nil {
		return err
	}
	if !s.MaintenancePresent {
		if liveExists || archiveExists {
			return ErrRelayAuthority
		}
		return nil
	}
	if liveExists && !liveMatches || archiveExists && !archiveMatches || liveExists && archiveExists || !liveExists && !archiveExists {
		return ErrRelayAuthority
	}
	if rollback {
		if !liveExists && os.Rename(archive, live) != nil {
			return ErrRelayAuthority
		}
	} else {
		if !archiveExists && os.Rename(live, archive) != nil {
			return ErrRelayAuthority
		}
	}
	if authoritySyncDirectory(filepath.Dir(live)) != nil || authoritySyncDirectory(operation) != nil {
		return ErrRelayAuthority
	}
	return nil
}

func (h *RelayAuthoritySnapshotHost) write(ctx context.Context, operation string, r relaytrust.SwitchRequest, expected string, rollback bool) error {
	s, err := h.snapshot(ctx, operation, r, expected)
	if err != nil {
		return err
	}
	// Validate the complete live mixture before the first write. Recovery accepts
	// only known before/after bytes with the original owner and private parent.
	for _, file := range s.Files {
		raw, err := authorityRead(filepath.Join(h.Options.Directory, filepath.FromSlash(file.Path)), file.UID, 32768)
		if err != nil || authorityHash(raw) != file.Before && authorityHash(raw) != file.After {
			return ErrRelayAuthority
		}
	}
	if ctx.Err() != nil || moveAuthorityMaintenance(h.Options.Directory, operation, s, rollback) != nil {
		return ErrRelayAuthority
	}
	if h.checkpoint != nil {
		h.checkpoint("maintenance")
	}
	side := "after"
	if rollback {
		side = "before"
	}
	// setup.json sorts last, so the manifest is the final active file replacement.
	for _, file := range s.Files {
		if ctx.Err() != nil {
			return ErrRelayAuthority
		}
		raw, err := authorityRead(filepath.Join(operation, "snapshot", side, filepath.FromSlash(file.Path)), 0, 32768)
		if err != nil {
			return ErrRelayAuthority
		}
		current, err := authorityRead(filepath.Join(h.Options.Directory, filepath.FromSlash(file.Path)), file.UID, 32768)
		if err != nil || authorityHash(current) != file.Before && authorityHash(current) != file.After {
			return ErrRelayAuthority
		}
		if !bytes.Equal(raw, current) && authorityReplace(filepath.Join(h.Options.Directory, filepath.FromSlash(file.Path)), file.UID, raw) != nil {
			return ErrRelayAuthority
		}
		// A prior rename may have succeeded before its directory sync failed.
		// Re-sync exact already-present bytes as well as newly replaced files.
		if authoritySyncMaterial(filepath.Join(h.Options.Directory, filepath.FromSlash(file.Path)), file.UID) != nil {
			return ErrRelayAuthority
		}
		if h.checkpoint != nil {
			h.checkpoint(file.Path)
		}
	}
	if CheckFiles(h.Options.Directory) != nil {
		return ErrRelayAuthority
	}
	ca, err := authorityRead(filepath.Join(h.Options.Directory, "secrets/issuer/ca.pem"), 0, 32768)
	if err != nil || h.Service.Reload(ctx, ca) != nil {
		return ErrRelayAuthority
	}
	if h.checkpoint != nil {
		h.checkpoint("reloaded")
	}
	return nil
}

func (h *RelayAuthoritySnapshotHost) Apply(ctx context.Context, operation string, r relaytrust.SwitchRequest, expected string) error {
	return h.write(ctx, operation, r, expected, false)
}
func (h *RelayAuthoritySnapshotHost) Restore(ctx context.Context, operation string, r relaytrust.SwitchRequest, expected string) error {
	return h.write(ctx, operation, r, expected, true)
}
func (h *RelayAuthoritySnapshotHost) Verify(ctx context.Context, operation string, r relaytrust.SwitchRequest, expected, phase string) (string, error) {
	s, err := h.snapshot(ctx, operation, r, expected)
	if err != nil || phase != "committed" && phase != "rolled_back" {
		return "", ErrRelayAuthority
	}
	for _, file := range s.Files {
		raw, err := authorityRead(filepath.Join(h.Options.Directory, filepath.FromSlash(file.Path)), file.UID, 32768)
		wanted := file.After
		if phase == "rolled_back" {
			wanted = file.Before
		}
		if err != nil || authorityHash(raw) != wanted {
			return "", ErrRelayAuthority
		}
	}
	live := filepath.Join(h.Options.Directory, "secrets/issuer/maintenance")
	archive := filepath.Join(operation, "retained-maintenance")
	if phase == "rolled_back" {
		live, archive = archive, live
	}
	if _, exists, err := authorityTreeMatches(live, s); err != nil || exists {
		return "", ErrRelayAuthority
	}
	matches, exists, err := authorityTreeMatches(archive, s)
	if err != nil || s.MaintenancePresent && (!exists || !matches) || !s.MaintenancePresent && exists || CheckFiles(h.Options.Directory) != nil {
		return "", ErrRelayAuthority
	}
	ca, err := authorityRead(filepath.Join(h.Options.Directory, "secrets/issuer/ca.pem"), 0, 32768)
	if err != nil {
		return "", ErrRelayAuthority
	}
	observed, err := h.Service.Observe(ctx, ca)
	wanted := r.NextLeaf
	if phase == "rolled_back" {
		wanted = r.PreviousLeaf
	}
	if err != nil || observed != wanted {
		return "", ErrRelayAuthority
	}
	return observed, nil
}
