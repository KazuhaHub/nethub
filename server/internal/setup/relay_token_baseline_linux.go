package setup

import (
	"context"
	"encoding/json"
	"path/filepath"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

type relayTokenBaseline struct {
	Manifest               string               `json:"manifest_sha256"`
	Runtime                []authorityTreeEntry `json:"runtime"`
	MaintenancePresent     bool                 `json:"maintenance_present"`
	Maintenance            []authorityTreeEntry `json:"maintenance"`
	OriginalBackupManifest string               `json:"original_backup_manifest_sha256"`
}

// The manifest binds all secret digests and owners. Runtime and maintenance
// content are additional input, since neither belongs to that secret manifest.
func currentRelayTokenBaseline(ctx context.Context, directory string) (string, error) {
	manifest, err := Load(directory)
	raw, readErr := authorityRead(filepath.Join(directory, "setup.json"), 0, 32768)
	if err != nil || readErr != nil || ctx.Err() != nil {
		return "", relaytoken.ErrTransition
	}
	value := relayTokenBaseline{Manifest: authorityHash(raw)}
	for _, name := range relayRuntimeFiles {
		data, err := authorityRead(filepath.Join(directory, filepath.FromSlash(name)), 65532, 32768)
		if err != nil || ctx.Err() != nil {
			return "", relaytoken.ErrTransition
		}
		value.Runtime = append(value.Runtime, authorityTreeEntry{Path: name, Digest: authorityHash(data)})
	}
	value.Maintenance, value.MaintenancePresent, err = authorityTree(filepath.Join(directory, "secrets/issuer/maintenance"))
	backup, backupErr := authorityRead(filepath.Join(manifest.BackupDirectory, "setup.json"), 0, 32768)
	if err != nil || backupErr != nil || ctx.Err() != nil {
		return "", relaytoken.ErrTransition
	}
	value.OriginalBackupManifest = authorityHash(backup)
	return authorityHash(authorityJSON(value)), nil
}

func snapshotRelayTokenBaseline(ctx context.Context, o relayTokenMaterialOptions) (string, error) {
	operation := filepath.Join(o.Directory, "token-transitions", o.Request.OperationID)
	raw, err := authorityRead(filepath.Join(operation, "snapshot.json"), 0, 1048576)
	var snapshot relayTokenMaterial
	if err != nil || ctx.Err() != nil || json.Unmarshal(raw, &snapshot) != nil || snapshot.Options != o {
		return "", relaytoken.ErrTransition
	}
	value := relayTokenBaseline{Maintenance: snapshot.Maintenance, MaintenancePresent: snapshot.MaintenancePresent,
		OriginalBackupManifest: snapshot.OriginalBackupManifest}
	files := map[string]string{}
	for _, file := range snapshot.Files {
		files[file.Path] = file.Before
	}
	value.Manifest = files["setup.json"]
	if !relayTrustDigest.MatchString(value.Manifest) || !relayTrustDigest.MatchString(value.OriginalBackupManifest) {
		return "", relaytoken.ErrTransition
	}
	for _, name := range relayRuntimeFiles {
		if !relayTrustDigest.MatchString(files[name]) {
			return "", relaytoken.ErrTransition
		}
		value.Runtime = append(value.Runtime, authorityTreeEntry{Path: name, Digest: files[name]})
	}
	return authorityHash(authorityJSON(value)), nil
}
