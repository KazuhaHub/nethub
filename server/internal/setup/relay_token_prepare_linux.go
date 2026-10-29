package setup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
	"golang.org/x/sys/unix"
)

// prepareRelayTokenMaterial only stages protected copies. The caller must own
// the shared operation lease, pin actual service identity and admit this request
// before creating its directory. No active file or service is changed here.
// Retried preparation retains its candidate and exact baseline. Conflicting or
// damaged partial output requires local review; it is never overwritten.
func prepareRelayTokenMaterial(ctx context.Context, o relayTokenMaterialOptions) (relaytoken.Snapshot, error) {
	empty := relaytoken.Snapshot{}
	if ctx.Err() != nil || !o.Request.Valid() || !filepath.IsAbs(o.Directory) || filepath.Clean(o.Directory) != o.Directory ||
		!filepath.IsAbs(o.SuccessorBackup) || filepath.Clean(o.SuccessorBackup) != o.SuccessorBackup ||
		!tokenPathsDisjoint(o.Directory, o.SuccessorBackup) {
		return empty, relaytoken.ErrTransition
	}
	operation := filepath.Join(o.Directory, "token-transitions", o.Request.OperationID)
	for _, directory := range []string{o.Directory, filepath.Dir(operation), operation} {
		if !(relayTokenJournal{directory: directory, request: o.Request}).valid() {
			return empty, relaytoken.ErrTransition
		}
	}
	if _, err := os.Lstat(filepath.Join(operation, "snapshot.json")); err == nil {
		verified, err := verifyRelayTokenMaterial(ctx, o)
		if err != nil || authoritySyncMaterial(filepath.Join(operation, "snapshot.json"), 0) != nil || ctx.Err() != nil {
			return empty, relaytoken.ErrTransition
		}
		return verified, nil
	} else if !os.IsNotExist(err) {
		return empty, relaytoken.ErrTransition
	}
	if tokenMaterialCopy(ctx, operation, "options.json", authorityJSON(o)) != nil {
		return empty, relaytoken.ErrTransition
	}
	before, err := Load(o.Directory)
	previous, readErr := authorityRead(filepath.Join(o.Directory, "secrets/authz/frp_token"), 65532, 65)
	if err != nil || readErr != nil {
		return empty, relaytoken.ErrTransition
	}
	candidatePath := filepath.Join(operation, "candidate")
	candidate, err := authorityRead(candidatePath, 0, 65)
	if _, statErr := os.Lstat(candidatePath); os.IsNotExist(statErr) {
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return empty, relaytoken.ErrTransition
		}
		candidate = append([]byte(hex.EncodeToString(entropy[:])), '\n')
		if tokenMaterialCopy(ctx, operation, "candidate", candidate) != nil {
			return empty, relaytoken.ErrTransition
		}
	} else if err != nil || statErr != nil {
		return empty, relaytoken.ErrTransition
	}
	after, err := relayTokenManifest(o.Directory, o.SuccessorBackup, before, previous, candidate)
	if err != nil || verifyFiles(o.Directory, before.Files) != nil || VerifyBackup(o.Directory, before.BackupDirectory) != nil {
		return empty, relaytoken.ErrTransition
	}
	owners := expectedOwners()
	for _, name := range relayRuntimeFiles {
		owners[name] = 65532
	}
	owners["setup.json"] = 0
	names := make([]string, 0, len(owners))
	for name := range owners {
		names = append(names, name)
	}
	slices.Sort(names)
	beforeData, afterData := map[string][]byte{}, map[string][]byte{}
	metadata := relayTokenMaterial{Version: 1, Options: o}
	backupManifest, err := authorityRead(filepath.Join(before.BackupDirectory, "setup.json"), 0, 32768)
	if err != nil {
		return empty, relaytoken.ErrTransition
	}
	metadata.OriginalBackupManifest = authorityHash(backupManifest)
	for _, name := range names {
		data, err := authorityRead(filepath.Join(o.Directory, filepath.FromSlash(name)), owners[name], 32768)
		if err != nil || ctx.Err() != nil {
			return empty, relaytoken.ErrTransition
		}
		next := data
		switch name {
		case "setup.json":
			canonical, _ := json.MarshalIndent(before, "", "  ")
			if !bytes.Equal(data, append(canonical, '\n')) {
				return empty, relaytoken.ErrTransition
			}
			canonical, _ = json.MarshalIndent(after, "", "  ")
			next = append(canonical, '\n')
		case "secrets/authz/frp_token", "secrets/frps/frp_token":
			if !bytes.Equal(data, previous) {
				return empty, relaytoken.ErrTransition
			}
			next = candidate
		}
		beforeData[name], afterData[name] = data, next
		metadata.Files = append(metadata.Files, authoritySnapshotFile{Path: name, Before: authorityHash(data), After: authorityHash(next), UID: owners[name]})
	}
	maintenance := filepath.Join(o.Directory, "secrets/issuer/maintenance")
	metadata.Maintenance, metadata.MaintenancePresent, err = authorityTree(maintenance)
	if err != nil || tokenMaterialCopy(ctx, operation, "preparation.json", authorityJSON(metadata)) != nil {
		return empty, relaytoken.ErrTransition
	}
	snapshot := filepath.Join(operation, "snapshot")
	for _, directory := range []string{snapshot, filepath.Join(snapshot, "before"), filepath.Join(snapshot, "after"),
		filepath.Join(snapshot, "maintenance"), o.SuccessorBackup, filepath.Join(o.SuccessorBackup, "maintenance")} {
		if ctx.Err() != nil || authorityPrivateDirectory(directory) != nil {
			return empty, relaytoken.ErrTransition
		}
	}
	for _, name := range names {
		if tokenMaterialCopy(ctx, filepath.Join(snapshot, "before"), name, beforeData[name]) != nil ||
			tokenMaterialCopy(ctx, filepath.Join(snapshot, "after"), name, afterData[name]) != nil ||
			tokenMaterialCopy(ctx, o.SuccessorBackup, name, afterData[name]) != nil {
			return empty, relaytoken.ErrTransition
		}
	}
	if tokenMaterialCopy(ctx, o.SuccessorBackup, ".gitignore", []byte("*\n")) != nil {
		return empty, relaytoken.ErrTransition
	}
	for _, entry := range metadata.Maintenance {
		for _, destination := range []string{filepath.Join(snapshot, "maintenance"), filepath.Join(o.SuccessorBackup, "maintenance")} {
			if entry.Directory {
				if authorityPrivateDirectory(filepath.Join(destination, filepath.FromSlash(entry.Path))) != nil {
					return empty, relaytoken.ErrTransition
				}
				continue
			}
			data, err := authorityRead(filepath.Join(maintenance, filepath.FromSlash(entry.Path)), 0, 1048576)
			if err != nil || authorityHash(data) != entry.Digest || tokenMaterialCopy(ctx, destination, entry.Path, data) != nil {
				return empty, relaytoken.ErrTransition
			}
		}
	}
	// Publishing metadata changes no active file. Independent verification below
	// must pass before this preparation can return a usable snapshot digest.
	if tokenMaterialCopy(ctx, operation, "snapshot.json", authorityJSON(metadata)) != nil {
		return empty, relaytoken.ErrTransition
	}
	return verifyRelayTokenMaterial(ctx, o)
}

// tokenMaterialCopy atomically creates one independent immutable private copy.
// A lost acknowledgement is recovered by exact readback and file/parent fsync.
func tokenMaterialCopy(ctx context.Context, root, name string, raw []byte) error {
	target := filepath.Join(root, filepath.FromSlash(name))
	if ctx.Err() != nil || filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || name == "." ||
		strings.Contains(name, "\\") || !tokenPathsContained(root, target) {
		return relaytoken.ErrTransition
	}
	actual, err := filepath.EvalSymlinks(root)
	info, statErr := os.Lstat(root)
	if os.Geteuid() != 0 || err != nil || actual != root || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || ownerUID(root) != 0 {
		return relaytoken.ErrTransition
	}
	var parents []string
	for parent := filepath.Dir(target); parent != root; parent = filepath.Dir(parent) {
		parents = append(parents, parent)
	}
	slices.Reverse(parents)
	for _, parent := range parents {
		if authorityPrivateDirectory(parent) != nil {
			return relaytoken.ErrTransition
		}
	}
	check := func() error {
		data, err := authorityRead(target, 0, int64(len(raw)))
		if err != nil || !bytes.Equal(data, raw) || authoritySyncMaterial(target, 0) != nil {
			return relaytoken.ErrTransition
		}
		return nil
	}
	if _, err := os.Lstat(target); err == nil {
		return check()
	} else if !os.IsNotExist(err) {
		return relaytoken.ErrTransition
	}
	file, err := os.CreateTemp(filepath.Dir(target), ".token-copy-*")
	if err != nil {
		return relaytoken.ErrTransition
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil || closed != nil || ctx.Err() != nil {
		return relaytoken.ErrTransition
	}
	err = unix.Renameat2(unix.AT_FDCWD, file.Name(), unix.AT_FDCWD, target, unix.RENAME_NOREPLACE)
	if err != nil && !errors.Is(err, unix.EEXIST) || authoritySyncDirectory(filepath.Dir(target)) != nil {
		return relaytoken.ErrTransition
	}
	return check()
}

func tokenPathsContained(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != "." && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
