package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

// publishRelayTokenMaterial advances only the two token files and setup.json.
// The caller owns the shared lease and actual service binding. A durable
// publishing phase and a complete independently verified successor are required
// before the first write. There is no rollback path to the compromised token.
func publishRelayTokenMaterial(ctx context.Context, o relayTokenMaterialOptions, intent relaytoken.Intent) error {
	return publishRelayTokenMaterialWithCheckpoint(ctx, o, intent, nil)
}

func publishRelayTokenMaterialWithCheckpoint(ctx context.Context, o relayTokenMaterialOptions, intent relaytoken.Intent, checkpoint func(string)) error {
	verified, err := verifyRelayTokenMaterial(ctx, o)
	if err != nil || !intent.Valid() || intent.Request != o.Request || intent.Snapshot != verified {
		return relaytoken.ErrTransition
	}
	operation := filepath.Join(o.Directory, "token-transitions", o.Request.OperationID)
	journal := relayTokenJournal{directory: operation, request: o.Request}
	saved, err := journal.ReadIntent(ctx)
	state, stateErr := journal.ReadState(ctx)
	if err != nil || saved != intent || stateErr != nil || state.Phase != "publishing" {
		return relaytoken.ErrTransition
	}
	raw, err := authorityRead(filepath.Join(operation, "snapshot.json"), 0, 1048576)
	var snapshot relayTokenMaterial
	if err != nil || json.Unmarshal(raw, &snapshot) != nil || authorityHash(raw) != intent.Snapshot.Digest {
		return relaytoken.ErrTransition
	}
	files := map[string]authoritySnapshotFile{}
	for _, file := range snapshot.Files {
		data, err := authorityRead(filepath.Join(o.Directory, filepath.FromSlash(file.Path)), file.UID, 32768)
		if err != nil || authorityHash(data) != file.Before && authorityHash(data) != file.After {
			return relaytoken.ErrTransition
		}
		files[file.Path] = file
	}
	maintenance, present, err := authorityTree(filepath.Join(o.Directory, "secrets/issuer/maintenance"))
	if err != nil || present != snapshot.MaintenancePresent || !bytes.Equal(authorityJSON(maintenance), authorityJSON(snapshot.Maintenance)) {
		return relaytoken.ErrTransition
	}
	// Explicit ordering keeps the manifest last, independently of metadata order.
	for _, name := range []string{"secrets/authz/frp_token", "secrets/frps/frp_token", "setup.json"} {
		file := files[name]
		target := filepath.Join(o.Directory, filepath.FromSlash(name))
		current, err := authorityRead(target, file.UID, 32768)
		next, nextErr := authorityRead(filepath.Join(operation, "snapshot/after", filepath.FromSlash(name)), 0, 32768)
		if ctx.Err() != nil || err != nil || nextErr != nil || authorityHash(next) != file.After ||
			authorityHash(current) != file.Before && authorityHash(current) != file.After {
			return relaytoken.ErrTransition
		}
		if !bytes.Equal(current, next) && authorityReplace(target, file.UID, next) != nil {
			return relaytoken.ErrTransition
		}
		if authoritySyncMaterial(target, file.UID) != nil {
			return relaytoken.ErrTransition
		}
		if checkpoint != nil {
			checkpoint(name)
		}
	}
	for _, file := range snapshot.Files {
		data, err := authorityRead(filepath.Join(o.Directory, filepath.FromSlash(file.Path)), file.UID, 32768)
		if ctx.Err() != nil || err != nil || authorityHash(data) != file.After {
			return relaytoken.ErrTransition
		}
	}
	// This establishes file publication only, never service reload or admission.
	return nil
}
