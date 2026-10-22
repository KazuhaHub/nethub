package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"github.com/KazuhaHub/nethub/server/internal/relaycert"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

type RelayAuthoritySnapshotOptions struct {
	Directory          string                   `json:"deployment"`
	CandidateDirectory string                   `json:"candidate"`
	CandidateBackup    string                   `json:"candidate_backup"`
	CustodyFile        string                   `json:"custody_file"`
	SuccessorBackup    string                   `json:"successor_backup"`
	Request            relaytrust.SwitchRequest `json:"request"`
}

type authoritySnapshotFile struct {
	Path   string `json:"path"`
	Before string `json:"before_sha256"`
	After  string `json:"after_sha256"`
	UID    int    `json:"uid"`
}

type authoritySnapshot struct {
	Version                int                           `json:"version"`
	Options                RelayAuthoritySnapshotOptions `json:"options"`
	Files                  []authoritySnapshotFile       `json:"files"`
	MaintenancePresent     bool                          `json:"maintenance_present"`
	Maintenance            []authorityTreeEntry          `json:"maintenance"`
	OriginalBackupManifest string                        `json:"original_backup_manifest_sha256"`
}

type authorityTreeEntry struct {
	Path      string `json:"path"`
	Directory bool   `json:"directory"`
	Digest    string `json:"sha256"`
}

func authorityHash(raw []byte) string {
	value := sha256.Sum256(raw)
	return hex.EncodeToString(value[:])
}

func authoritySyncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return ErrRelayAuthority
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrRelayAuthority
	}
	return nil
}

func authorityPrivateDirectory(path string) error {
	parent := filepath.Dir(path)
	actual, err := filepath.EvalSymlinks(parent)
	info, statErr := os.Lstat(parent)
	if err != nil || actual != parent || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || ownerUID(parent) != 0 {
		return ErrRelayAuthority
	}
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return ErrRelayAuthority
	}
	actual, err = filepath.EvalSymlinks(path)
	info, statErr = os.Lstat(path)
	if err != nil || actual != path || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || ownerUID(path) != 0 || authoritySyncDirectory(parent) != nil {
		return ErrRelayAuthority
	}
	return nil
}

func authorityRead(path string, uid int, maximum int64) ([]byte, error) {
	actual, err := filepath.EvalSymlinks(path)
	before, statErr := os.Lstat(path)
	parent, parentErr := os.Lstat(filepath.Dir(path))
	if err != nil || actual != path || statErr != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() > maximum || ownerUID(path) != uid {
		return nil, ErrRelayAuthority
	}
	if parentErr != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 || ownerUID(filepath.Dir(path)) != uid {
		return nil, ErrRelayAuthority
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, ErrRelayAuthority
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrRelayAuthority
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, ErrRelayAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(before, after) || int64(len(raw)) > maximum || before.Size() != int64(len(raw)) || !before.ModTime().Equal(after.ModTime()) {
		return nil, ErrRelayAuthority
	}
	return raw, nil
}

func authorityCopy(root, path string, raw []byte) error {
	parent := filepath.Dir(path)
	var missing []string
	for current := parent; current != root; current = filepath.Dir(current) {
		rel, err := filepath.Rel(root, current)
		if err != nil || rel == ".." || filepath.IsAbs(rel) {
			return ErrRelayAuthority
		}
		missing = append(missing, current)
		if filepath.Dir(current) == current {
			return ErrRelayAuthority
		}
	}
	slices.Reverse(missing)
	for _, dir := range missing {
		if authorityPrivateDirectory(dir) != nil {
			return ErrRelayAuthority
		}
	}
	if writePrivate(path, raw) != nil || authoritySyncDirectory(parent) != nil {
		return ErrRelayAuthority
	}
	return nil
}

func authorityLeaf(raw []byte) string {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return ""
	}
	return authorityHash(block.Bytes)
}

func authorityJSON(v any) []byte { raw, _ := json.Marshal(v); return append(raw, '\n') }

func authorityTree(root string) ([]authorityTreeEntry, bool, error) {
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return []authorityTreeEntry{}, false, nil
	}
	var entries []authorityTreeEntry
	var total int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || len(entries) > 2048 {
			return ErrRelayAuthority
		}
		info, err := os.Lstat(path)
		actual, resolveErr := filepath.EvalSymlinks(path)
		if err != nil || resolveErr != nil || actual != path || ownerUID(path) != 0 {
			return ErrRelayAuthority
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return ErrRelayAuthority
		}
		if entry.IsDir() {
			if info.Mode().Perm() != 0700 {
				return ErrRelayAuthority
			}
			if rel != "." {
				entries = append(entries, authorityTreeEntry{Path: filepath.ToSlash(rel), Directory: true})
			}
			return nil
		}
		raw, err := authorityRead(path, 0, 1048576)
		total += int64(len(raw))
		if err != nil || total > 64*1048576 {
			return ErrRelayAuthority
		}
		entries = append(entries, authorityTreeEntry{Path: filepath.ToSlash(rel), Digest: authorityHash(raw)})
		return nil
	})
	if entries == nil {
		entries = []authorityTreeEntry{}
	}
	return entries, true, err
}

// PrepareRelayAuthoritySnapshot stages exact independent before/after copies.
// It changes no active authority/runtime/service and creates no database fence.
// Root-owned partial output is retained on failure; it is never overwritten.
// Its operation directory blocks ordinary renewal until the journal resolves.
func PrepareRelayAuthoritySnapshot(ctx context.Context, o RelayAuthoritySnapshotOptions) (string, error) {
	if os.Geteuid() != 0 || ctx.Err() != nil || !o.Request.Valid() || !filepath.IsAbs(o.Directory) || filepath.Clean(o.Directory) != o.Directory {
		return "", ErrRelayAuthority
	}
	actual, err := filepath.EvalSymlinks(o.Directory)
	if err != nil || actual != o.Directory {
		return "", ErrRelayAuthority
	}
	lease, err := hostlease.Acquire(filepath.Join(o.Directory, "relay-operation.lock"))
	if err != nil {
		return "", ErrRelayAuthority
	}
	defer lease.Close()
	root := filepath.Join(o.Directory, "authority-transitions")
	if authorityPrivateDirectory(root) != nil {
		return "", ErrRelayAuthority
	}
	operation := filepath.Join(root, o.Request.ID)
	if authorityPrivateDirectory(operation) != nil {
		return "", ErrRelayAuthority
	}
	return prepareAuthoritySnapshot(ctx, operation, o)
}

func prepareAuthoritySnapshot(ctx context.Context, operation string, o RelayAuthoritySnapshotOptions) (string, error) {
	if ctx.Err() != nil || os.Geteuid() != 0 || !o.Request.Valid() || operation != filepath.Join(o.Directory, "authority-transitions", o.Request.ID) {
		return "", ErrRelayAuthority
	}
	candidate, err := relayauthority.Load(o.CandidateDirectory, time.Now())
	if err != nil {
		return "", ErrRelayAuthority
	}
	if _, err := relayauthority.VerifyCustody(o.CandidateDirectory, o.CandidateBackup, o.CustodyFile, time.Now()); err != nil || candidate.Metadata.Previous != o.Request.PreviousRoot || candidate.Metadata.Next != o.Request.NextRoot || authorityLeaf(candidate.Material.Certificate) != o.Request.NextLeaf {
		return "", ErrRelayAuthority
	}
	for _, path := range []string{o.CandidateDirectory, o.CandidateBackup, o.CustodyFile, o.SuccessorBackup} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || pathsOverlap(o.Directory, path) {
			return "", ErrRelayAuthority
		}
	}
	for _, path := range []string{o.CandidateDirectory, o.CandidateBackup, o.CustodyFile} {
		if pathsOverlap(path, o.SuccessorBackup) {
			return "", ErrRelayAuthority
		}
	}
	metadata := filepath.Join(operation, "snapshot.json")
	if _, err := os.Lstat(metadata); err == nil {
		return verifyAuthoritySnapshot(operation, o)
	} else if !os.IsNotExist(err) {
		return "", ErrRelayAuthority
	}
	if CheckFiles(o.Directory) != nil {
		return "", ErrRelayAuthority
	}
	before, err := Load(o.Directory)
	if err != nil || candidate.Metadata.ServerName != before.Config.ConsoleHost || pathsOverlap(before.BackupDirectory, o.SuccessorBackup) {
		return "", ErrRelayAuthority
	}
	for _, path := range []string{o.CandidateDirectory, o.CandidateBackup, o.CustodyFile, o.SuccessorBackup} {
		if pathsOverlap(before.BackupDirectory, path) {
			return "", ErrRelayAuthority
		}
	}
	ca, err := authorityRead(filepath.Join(o.Directory, "secrets/issuer/ca.pem"), 0, 32768)
	if err != nil {
		return "", ErrRelayAuthority
	}
	key, err := authorityRead(filepath.Join(o.Directory, "secrets/issuer/ca-key.pem"), 0, 32768)
	if err != nil {
		return "", ErrRelayAuthority
	}
	rootID, err := relaycert.AuthorityIdentity(ca, key)
	runtime, errRuntime := readRelayRuntime(o.Directory, true)
	if err != nil || errRuntime != nil || rootID != o.Request.PreviousRoot || authorityLeaf(runtime[0]) != o.Request.PreviousLeaf {
		return "", ErrRelayAuthority
	}
	snapshotRoot := filepath.Join(operation, "snapshot")
	if _, err := os.Lstat(snapshotRoot); !os.IsNotExist(err) {
		return "", ErrRelayAuthority
	}
	if authorityPrivateDirectory(snapshotRoot) != nil {
		return "", ErrRelayAuthority
	}
	for _, name := range []string{"before", "after", "maintenance"} {
		if authorityPrivateDirectory(filepath.Join(snapshotRoot, name)) != nil {
			return "", ErrRelayAuthority
		}
	}
	replacements := map[string][]byte{"secrets/issuer/ca.pem": candidate.Material.CA, "secrets/issuer/ca-key.pem": candidate.Material.CAKey, "secrets/issuer/initial/relay-cert.pem": candidate.Material.Certificate, "secrets/issuer/initial/relay-key.pem": candidate.Material.Key,
		"runtime/relay/relay-cert.pem": candidate.Material.Certificate, "runtime/relay/relay-key.pem": candidate.Material.Key, "runtime/trust/relay-ca.pem": candidate.Material.CA}
	after := before
	after.Files = append([]SecretFile(nil), before.Files...)
	after.BackupDirectory = o.SuccessorBackup
	for i, file := range after.Files {
		if raw, ok := replacements[file.Path]; ok {
			after.Files[i].SHA256 = authorityHash(raw)
			after.Files[i].Size = int64(len(raw))
		}
	}
	oldManifest, err := authorityRead(filepath.Join(o.Directory, "setup.json"), 0, 32768)
	if err != nil {
		return "", ErrRelayAuthority
	}
	newManifest, err := json.MarshalIndent(after, "", "  ")
	if err != nil {
		return "", ErrRelayAuthority
	}
	newManifest = append(newManifest, '\n')
	owners := expectedOwners()
	for _, path := range relayRuntimeFiles {
		owners[path] = 65532
	}
	owners["setup.json"] = 0
	paths := make([]string, 0, len(owners))
	for path := range owners {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	s := authoritySnapshot{Version: 1, Options: o}
	backupManifest, err := authorityRead(filepath.Join(before.BackupDirectory, "setup.json"), 0, 32768)
	if err != nil {
		return "", ErrRelayAuthority
	}
	s.OriginalBackupManifest = authorityHash(backupManifest)
	for _, path := range paths {
		if ctx.Err() != nil {
			return "", ErrRelayAuthority
		}
		raw, err := authorityRead(filepath.Join(o.Directory, filepath.FromSlash(path)), owners[path], 32768)
		if err != nil {
			return "", ErrRelayAuthority
		}
		next := raw
		if replacement, ok := replacements[path]; ok {
			next = replacement
		}
		if path == "setup.json" {
			raw = oldManifest
			next = newManifest
		}
		if authorityCopy(snapshotRoot, filepath.Join(snapshotRoot, "before", filepath.FromSlash(path)), raw) != nil || authorityCopy(snapshotRoot, filepath.Join(snapshotRoot, "after", filepath.FromSlash(path)), next) != nil {
			return "", ErrRelayAuthority
		}
		s.Files = append(s.Files, authoritySnapshotFile{Path: path, Before: authorityHash(raw), After: authorityHash(next), UID: owners[path]})
	}
	maintenance := filepath.Join(o.Directory, "secrets/issuer/maintenance")
	s.Maintenance, s.MaintenancePresent, err = authorityTree(maintenance)
	if err != nil {
		return "", ErrRelayAuthority
	}
	for _, entry := range s.Maintenance {
		target := filepath.Join(snapshotRoot, "maintenance", filepath.FromSlash(entry.Path))
		if entry.Directory {
			if authorityPrivateDirectory(target) != nil {
				return "", ErrRelayAuthority
			}
			continue
		}
		raw, err := authorityRead(filepath.Join(maintenance, filepath.FromSlash(entry.Path)), 0, 1048576)
		if err != nil || authorityCopy(snapshotRoot, target, raw) != nil {
			return "", ErrRelayAuthority
		}
	}
	if _, err := os.Lstat(o.SuccessorBackup); !os.IsNotExist(err) {
		return "", ErrRelayAuthority
	}
	if authorityPrivateDirectory(o.SuccessorBackup) != nil {
		return "", ErrRelayAuthority
	}
	// The backup root must be new; exclusive writes retain partial output on error.
	for _, file := range after.Files {
		raw, err := authorityRead(filepath.Join(snapshotRoot, "after", filepath.FromSlash(file.Path)), 0, 32768)
		if err != nil || authorityCopy(o.SuccessorBackup, filepath.Join(o.SuccessorBackup, filepath.FromSlash(file.Path)), raw) != nil {
			return "", ErrRelayAuthority
		}
	}
	if authorityCopy(o.SuccessorBackup, filepath.Join(o.SuccessorBackup, "setup.json"), newManifest) != nil || authoritySyncDirectory(snapshotRoot) != nil {
		return "", ErrRelayAuthority
	}
	if VerifyBackup(filepath.Join(snapshotRoot, "before"), before.BackupDirectory) != nil || VerifyBackup(filepath.Join(snapshotRoot, "after"), o.SuccessorBackup) != nil {
		return "", ErrRelayAuthority
	}
	if authorityCopy(operation, metadata, authorityJSON(s)) != nil {
		return "", ErrRelayAuthority
	}
	return verifyAuthoritySnapshot(operation, o)
}

func verifyAuthoritySnapshot(operation string, o RelayAuthoritySnapshotOptions) (string, error) {
	raw, err := authorityRead(filepath.Join(operation, "snapshot.json"), 0, 1048576)
	var s authoritySnapshot
	if err != nil || json.Unmarshal(raw, &s) != nil || !bytes.Equal(raw, authorityJSON(s)) || s.Version != 1 || s.Options != o || len(s.Files) != 26 {
		return "", ErrRelayAuthority
	}
	root := filepath.Join(operation, "snapshot")
	owners := expectedOwners()
	for _, path := range relayRuntimeFiles {
		owners[path] = 65532
	}
	owners["setup.json"] = 0
	for _, file := range s.Files {
		uid, ok := owners[file.Path]
		if !ok || file.UID != uid {
			return "", ErrRelayAuthority
		}
		delete(owners, file.Path)
		for _, side := range []string{"before", "after"} {
			data, err := authorityRead(filepath.Join(root, side, filepath.FromSlash(file.Path)), 0, 32768)
			expected := file.Before
			if side == "after" {
				expected = file.After
			}
			if err != nil || authorityHash(data) != expected {
				return "", ErrRelayAuthority
			}
		}
	}
	if len(owners) != 0 {
		return "", ErrRelayAuthority
	}
	before, err := Load(filepath.Join(root, "before"))
	if err != nil {
		return "", ErrRelayAuthority
	}
	after, err := Load(filepath.Join(root, "after"))
	if err != nil || after.BackupDirectory != o.SuccessorBackup || pathsOverlap(before.BackupDirectory, o.SuccessorBackup) {
		return "", ErrRelayAuthority
	}
	candidate, err := relayauthority.Load(o.CandidateDirectory, time.Now())
	if err != nil || before.ConfirmedAt == nil || candidate.Metadata.ServerName != before.Config.ConsoleHost {
		return "", ErrRelayAuthority
	}
	expected := before
	expected.Files = append([]SecretFile(nil), before.Files...)
	expected.BackupDirectory = o.SuccessorBackup
	replacements := map[string][]byte{"secrets/issuer/ca.pem": candidate.Material.CA, "secrets/issuer/ca-key.pem": candidate.Material.CAKey, "secrets/issuer/initial/relay-cert.pem": candidate.Material.Certificate, "secrets/issuer/initial/relay-key.pem": candidate.Material.Key,
		"runtime/relay/relay-cert.pem": candidate.Material.Certificate, "runtime/relay/relay-key.pem": candidate.Material.Key, "runtime/trust/relay-ca.pem": candidate.Material.CA}
	for i, file := range expected.Files {
		if data, ok := replacements[file.Path]; ok {
			expected.Files[i].SHA256 = authorityHash(data)
			expected.Files[i].Size = int64(len(data))
		}
	}
	if !bytes.Equal(authorityJSON(expected), authorityJSON(after)) {
		return "", ErrRelayAuthority
	}
	for _, file := range s.Files {
		data, err := authorityRead(filepath.Join(root, "after", filepath.FromSlash(file.Path)), 0, 32768)
		if err != nil {
			return "", ErrRelayAuthority
		}
		if replacement, ok := replacements[file.Path]; ok {
			if !bytes.Equal(data, replacement) {
				return "", ErrRelayAuthority
			}
		} else if file.Path != "setup.json" && file.Before != file.After {
			return "", ErrRelayAuthority
		}
	}
	oldCA, err := authorityRead(filepath.Join(root, "before/secrets/issuer/ca.pem"), 0, 32768)
	if err != nil {
		return "", ErrRelayAuthority
	}
	oldKey, err := authorityRead(filepath.Join(root, "before/secrets/issuer/ca-key.pem"), 0, 32768)
	if err != nil {
		return "", ErrRelayAuthority
	}
	oldRoot, err := relaycert.AuthorityIdentity(oldCA, oldKey)
	oldLeaf, leafErr := authorityRead(filepath.Join(root, "before/runtime/relay/relay-cert.pem"), 0, 32768)
	if err != nil || leafErr != nil || oldRoot != o.Request.PreviousRoot || authorityLeaf(oldLeaf) != o.Request.PreviousLeaf {
		return "", ErrRelayAuthority
	}
	oldLeafKey, err := authorityRead(filepath.Join(root, "before/runtime/relay/relay-key.pem"), 0, 32768)
	if err != nil {
		return "", ErrRelayAuthority
	}
	oldTrust, err := authorityRead(filepath.Join(root, "before/runtime/trust/relay-ca.pem"), 0, 32768)
	if err != nil || !bytes.Equal(oldTrust, oldCA) {
		return "", ErrRelayAuthority
	}
	if _, err := relaycert.Assess(oldCA, oldLeaf, oldLeafKey, before.Config.ConsoleHost, time.Now()); err != nil {
		return "", ErrRelayAuthority
	}
	for _, side := range []string{"before", "after"} {
		entries, _, err := authorityTree(filepath.Join(root, side))
		if err != nil {
			return "", ErrRelayAuthority
		}
		count := 0
		for _, entry := range entries {
			if !entry.Directory {
				count++
			}
		}
		if count != 26 {
			return "", ErrRelayAuthority
		}
	}
	if VerifyBackup(filepath.Join(root, "before"), before.BackupDirectory) != nil || VerifyBackup(filepath.Join(root, "after"), o.SuccessorBackup) != nil {
		return "", ErrRelayAuthority
	}
	backupManifest, err := authorityRead(filepath.Join(before.BackupDirectory, "setup.json"), 0, 32768)
	if err != nil || authorityHash(backupManifest) != s.OriginalBackupManifest {
		return "", ErrRelayAuthority
	}
	originalBackup, err := Load(before.BackupDirectory)
	if err != nil || originalBackup.Config != before.Config || !bytes.Equal(authorityJSON(originalBackup.Files), authorityJSON(before.Files)) {
		return "", ErrRelayAuthority
	}
	newBackupManifest, err := authorityRead(filepath.Join(o.SuccessorBackup, "setup.json"), 0, 32768)
	if err != nil {
		return "", ErrRelayAuthority
	}
	stagedManifest, err := authorityRead(filepath.Join(root, "after/setup.json"), 0, 32768)
	if err != nil || !bytes.Equal(newBackupManifest, stagedManifest) {
		return "", ErrRelayAuthority
	}
	tree, _, err := authorityTree(filepath.Join(root, "maintenance"))
	if err != nil || !bytes.Equal(authorityJSON(tree), authorityJSON(s.Maintenance)) || !s.MaintenancePresent && len(tree) != 0 {
		return "", ErrRelayAuthority
	}
	return authorityHash(raw), nil
}
