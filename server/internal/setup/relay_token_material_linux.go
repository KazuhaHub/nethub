package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

type relayTokenMaterialOptions struct {
	Directory       string             `json:"deployment"`
	SuccessorBackup string             `json:"successor_backup"`
	Request         relaytoken.Request `json:"request"`
}

type relayTokenMaterial struct {
	Version                int                       `json:"version"`
	Options                relayTokenMaterialOptions `json:"options"`
	Files                  []authoritySnapshotFile   `json:"files"`
	MaintenancePresent     bool                      `json:"maintenance_present"`
	Maintenance            []authorityTreeEntry      `json:"maintenance"`
	OriginalBackupManifest string                    `json:"original_backup_manifest_sha256"`
}

// verifyRelayTokenMaterial checks a retained exact before/after snapshot and a
// complete independent successor backup. It creates or publishes nothing and
// does not observe live services. The host coordinator must hold its lease,
// compare the returned digest with its durable intent, and enforce admission.
func verifyRelayTokenMaterial(ctx context.Context, o relayTokenMaterialOptions) (relaytoken.Snapshot, error) {
	var empty relaytoken.Snapshot
	if os.Geteuid() != 0 || ctx.Err() != nil || !o.Request.Valid() ||
		!filepath.IsAbs(o.Directory) || filepath.Clean(o.Directory) != o.Directory ||
		!filepath.IsAbs(o.SuccessorBackup) || filepath.Clean(o.SuccessorBackup) != o.SuccessorBackup {
		return empty, relaytoken.ErrTransition
	}
	operation := filepath.Join(o.Directory, "token-transitions", o.Request.OperationID)
	for _, directory := range []string{o.Directory, filepath.Dir(operation), operation, o.SuccessorBackup} {
		if !(relayTokenJournal{directory: directory, request: o.Request}).valid() {
			return empty, relaytoken.ErrTransition
		}
	}
	raw, err := authorityRead(filepath.Join(operation, "snapshot.json"), 0, 1048576)
	var saved relayTokenMaterial
	if err != nil || json.Unmarshal(raw, &saved) != nil || !bytes.Equal(raw, authorityJSON(saved)) ||
		saved.Version != 1 || saved.Options != o || !relayTrustDigest.MatchString(saved.OriginalBackupManifest) {
		return empty, relaytoken.ErrTransition
	}
	root := filepath.Join(operation, "snapshot")
	owners := expectedOwners()
	for _, name := range relayRuntimeFiles {
		owners[name] = 65532
	}
	owners["setup.json"] = 0
	if len(saved.Files) != len(owners) {
		return empty, relaytoken.ErrTransition
	}
	sides := map[string]map[string]authorityTreeEntry{"before": {}, "after": {}}
	var observed []os.FileInfo
	for _, file := range saved.Files {
		owner, ok := owners[file.Path]
		if !ok || file.UID != owner || !relayTrustDigest.MatchString(file.Before) || !relayTrustDigest.MatchString(file.After) {
			return empty, relaytoken.ErrTransition
		}
		delete(owners, file.Path)
		for _, side := range []string{"before", "after"} {
			target := filepath.Join(root, side, filepath.FromSlash(file.Path))
			data, readErr := authorityRead(target, 0, 32768)
			expected := file.Before
			if side == "after" {
				expected = file.After
			}
			if ctx.Err() != nil || readErr != nil || authorityHash(data) != expected {
				return empty, relaytoken.ErrTransition
			}
			if file.Path != "setup.json" && file.Path != "secrets/authz/frp_token" && file.Path != "secrets/frps/frp_token" && file.Before != file.After {
				return empty, relaytoken.ErrTransition
			}
			sides[side][file.Path] = authorityTreeEntry{Path: file.Path, Digest: expected}
			info, statErr := os.Stat(target)
			if statErr != nil || tokenFileAlias(observed, info) {
				return empty, relaytoken.ErrTransition
			}
			observed = append(observed, info)
		}
	}
	if len(owners) != 0 {
		return empty, relaytoken.ErrTransition
	}
	beforeRoot, afterRoot := filepath.Join(root, "before"), filepath.Join(root, "after")
	before, err := Load(beforeRoot)
	after, afterErr := Load(afterRoot)
	old, oldErr := authorityRead(filepath.Join(beforeRoot, "secrets/authz/frp_token"), 0, 65)
	other, otherErr := authorityRead(filepath.Join(beforeRoot, "secrets/frps/frp_token"), 0, 65)
	candidate, candidateErr := authorityRead(filepath.Join(operation, "candidate"), 0, 65)
	if err != nil || afterErr != nil || oldErr != nil || otherErr != nil || candidateErr != nil || !bytes.Equal(old, other) {
		return empty, relaytoken.ErrTransition
	}
	planned, err := relayTokenManifest(o.Directory, o.SuccessorBackup, before, old, candidate)
	if err != nil || !bytes.Equal(authorityJSON(after), authorityJSON(planned)) {
		return empty, relaytoken.ErrTransition
	}
	if verifyFiles(beforeRoot, before.Files) != nil || verifyFiles(afterRoot, after.Files) != nil {
		return empty, relaytoken.ErrTransition
	}
	for _, side := range []string{"before", "after"} {
		dir := filepath.Join(root, side)
		manifest, loadErr := Load(dir)
		data, readErr := authorityRead(filepath.Join(dir, "setup.json"), 0, 32768)
		canonical, jsonErr := json.MarshalIndent(manifest, "", "  ")
		if loadErr != nil || readErr != nil || jsonErr != nil || !bytes.Equal(data, append(canonical, '\n')) ||
			!tokenExactTree(dir, sides[side]) {
			return empty, relaytoken.ErrTransition
		}
	}
	maintenance, present, err := authorityTree(filepath.Join(root, "maintenance"))
	if err != nil || !present || !bytes.Equal(authorityJSON(maintenance), authorityJSON(saved.Maintenance)) ||
		!saved.MaintenancePresent && len(maintenance) != 0 {
		return empty, relaytoken.ErrTransition
	}
	oldBackup, err := authorityRead(filepath.Join(before.BackupDirectory, "setup.json"), 0, 32768)
	original, loadErr := Load(before.BackupDirectory)
	if err != nil || loadErr != nil || authorityHash(oldBackup) != saved.OriginalBackupManifest ||
		!sameConfig(original.Config, before.Config) || !bytes.Equal(authorityJSON(original.Files), authorityJSON(before.Files)) ||
		VerifyBackup(beforeRoot, before.BackupDirectory) != nil || VerifyBackup(afterRoot, o.SuccessorBackup) != nil {
		return empty, relaytoken.ErrTransition
	}
	for _, target := range []string{filepath.Join(operation, "candidate"), filepath.Join(before.BackupDirectory, "setup.json")} {
		info, err := os.Stat(target)
		if err != nil || tokenFileAlias(observed, info) {
			return empty, relaytoken.ErrTransition
		}
		observed = append(observed, info)
	}
	for _, file := range original.Files {
		target := filepath.Join(before.BackupDirectory, filepath.FromSlash(file.Path))
		if _, err := authorityRead(target, 0, 32768); err != nil {
			return empty, relaytoken.ErrTransition
		}
		info, err := os.Stat(target)
		if err != nil || tokenFileAlias(observed, info) {
			return empty, relaytoken.ErrTransition
		}
		observed = append(observed, info)
	}
	backupTree := map[string]authorityTreeEntry{}
	for name, entry := range sides["after"] {
		backupTree[name] = entry
		target := filepath.Join(o.SuccessorBackup, filepath.FromSlash(name))
		data, readErr := authorityRead(target, 0, 32768)
		info, statErr := os.Stat(target)
		if ctx.Err() != nil || readErr != nil || authorityHash(data) != entry.Digest || statErr != nil || tokenFileAlias(observed, info) {
			return empty, relaytoken.ErrTransition
		}
		observed = append(observed, info)
	}
	backupTree[".gitignore"] = authorityTreeEntry{Path: ".gitignore", Digest: authorityHash([]byte("*\n"))}
	backupTree["maintenance"] = authorityTreeEntry{Path: "maintenance", Directory: true}
	for _, entry := range maintenance {
		name := "maintenance/" + entry.Path
		entry.Path = name
		backupTree[name] = entry
	}
	if !tokenExactTree(o.SuccessorBackup, backupTree) {
		return empty, relaytoken.ErrTransition
	}
	for _, entry := range maintenance {
		if entry.Directory {
			continue
		}
		for _, directory := range []string{filepath.Join(root, "maintenance"), filepath.Join(o.SuccessorBackup, "maintenance")} {
			target := filepath.Join(directory, filepath.FromSlash(entry.Path))
			info, err := os.Stat(target)
			if err != nil || tokenFileAlias(observed, info) {
				return empty, relaytoken.ErrTransition
			}
			observed = append(observed, info)
		}
	}
	return relaytoken.Snapshot{Digest: authorityHash(raw), Before: authorityHash(old), After: authorityHash(candidate)}, nil
}

func tokenFileAlias(previous []os.FileInfo, current os.FileInfo) bool {
	for _, info := range previous {
		if os.SameFile(info, current) {
			return true
		}
	}
	return false
}

func tokenExactTree(directory string, files map[string]authorityTreeEntry) bool {
	expected := map[string]authorityTreeEntry{}
	for name, entry := range files {
		expected[name] = entry
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			expected[parent] = authorityTreeEntry{Path: parent, Directory: true}
		}
	}
	actual, present, err := authorityTree(directory)
	if err != nil || !present || len(actual) != len(expected) {
		return false
	}
	for _, entry := range actual {
		if want, ok := expected[entry.Path]; !ok || want != entry {
			return false
		}
	}
	return true
}
