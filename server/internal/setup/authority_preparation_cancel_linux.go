package setup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"github.com/KazuhaHub/nethub/server/internal/relaycert"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

// VerifyPreparation inspects the original live deployment independently of any
// partial staged material. Unknown partial files are retained and never read as
// authority for recovery. Current certificate/name/TLS checks remain mandatory.
func (h *RelayAuthoritySnapshotHost) VerifyPreparation(ctx context.Context, operation string, request relaytrust.SwitchRequest) (string, string, error) {
	if h == nil || h.Service == nil || os.Geteuid() != 0 || ctx.Err() != nil || !request.Valid() || request != h.Options.Request || operation != filepath.Join(h.Options.Directory, "authority-transitions", request.ID) || h.checkServiceBinding() != nil || CheckFiles(h.Options.Directory) != nil {
		return "", "", ErrRelayAuthority
	}
	o := h.Options
	manifest, err := Load(o.Directory)
	if err != nil {
		return "", "", ErrRelayAuthority
	}
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
	// Reuse the immutable snapshot record shape solely as a digest of the
	// verified current baseline. This does not create or complete a snapshot.
	baseline := authoritySnapshot{Version: 1, Options: o}
	for _, path := range paths {
		if ctx.Err() != nil {
			return "", "", ErrRelayAuthority
		}
		raw, err := authorityRead(filepath.Join(o.Directory, filepath.FromSlash(path)), owners[path], 32768)
		if err != nil {
			return "", "", ErrRelayAuthority
		}
		baseline.Files = append(baseline.Files, authoritySnapshotFile{Path: path, Before: authorityHash(raw), UID: owners[path]})
	}
	backupManifest, err := authorityRead(filepath.Join(manifest.BackupDirectory, "setup.json"), 0, 32768)
	if err != nil {
		return "", "", ErrRelayAuthority
	}
	baseline.OriginalBackupManifest = authorityHash(backupManifest)
	backup, err := Load(manifest.BackupDirectory)
	if err != nil || backup.Config != manifest.Config || !bytes.Equal(authorityJSON(backup.Files), authorityJSON(manifest.Files)) {
		return "", "", ErrRelayAuthority
	}
	baseline.Maintenance, baseline.MaintenancePresent, err = authorityTree(filepath.Join(o.Directory, "secrets/issuer/maintenance"))
	if err != nil {
		return "", "", ErrRelayAuthority
	}
	// An archived maintenance tree implies live migration already began, even
	// if another file was later restored. Only normal transition recovery may
	// resolve that state; preparation cancellation never moves it back.
	if _, err := os.Lstat(filepath.Join(operation, "retained-maintenance")); !os.IsNotExist(err) {
		return "", "", ErrRelayAuthority
	}
	ca, err := authorityRead(filepath.Join(o.Directory, "secrets/issuer/ca.pem"), 0, 32768)
	if err != nil {
		return "", "", ErrRelayAuthority
	}
	key, err := authorityRead(filepath.Join(o.Directory, "secrets/issuer/ca-key.pem"), 0, 32768)
	if err != nil {
		return "", "", ErrRelayAuthority
	}
	root, err := relaycert.AuthorityIdentity(ca, key)
	if err != nil || root != request.PreviousRoot {
		return "", "", ErrRelayAuthority
	}
	observed, err := h.Service.Observe(ctx, ca)
	if err != nil || observed != request.PreviousLeaf || ctx.Err() != nil {
		return "", "", ErrRelayAuthority
	}
	return authorityHash(authorityJSON(baseline)), observed, nil
}

// CancelBoundRelayAuthorityPreparation requires explicit original options when
// initialization did not leave a complete recoverable snapshot. It binds the
// exact healthy original service/database and delegates serialized cancellation;
// it never loads, repairs or deletes a partial candidate or successor backup.
func CancelBoundRelayAuthorityPreparation(ctx context.Context, o RelayAuthoritySnapshotOptions, project, composeFile string) (relayauthority.TransitionState, error) {
	var state relayauthority.TransitionState
	if os.Geteuid() != 0 || ctx.Err() != nil || !o.Request.Valid() || !filepath.IsAbs(o.Directory) || filepath.Clean(o.Directory) != o.Directory || !relayTrustDigest.MatchString(o.ServiceFingerprint) {
		return state, ErrRelayAuthority
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	service, err := BindRelayAuthorityService(ctx, o.Directory, project, composeFile, o.ServiceFingerprint)
	if err != nil {
		return state, ErrRelayAuthority
	}
	binding, err := service.host.database(ctx)
	if err != nil {
		return state, ErrRelayAuthority
	}
	run, err := guiissuer.NewDockerSQLRunner(binding)
	if err != nil {
		return state, ErrRelayAuthority
	}
	publisher := &relaytrust.Publisher{Run: relaytrust.SQLRunner(run), ServerName: service.binding.Config.ConsoleHost}
	host := &RelayAuthoritySnapshotHost{Options: o, Service: service}
	return (relayauthority.Transition{Directory: o.Directory, ServerName: service.binding.Config.ConsoleHost, Request: o.Request, Host: host, Trust: publisher}).CancelPreparation(ctx)
}
