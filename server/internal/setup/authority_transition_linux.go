package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

var authorityOperationID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// RunBoundRelayAuthorityTransition composes the real protected database, file
// journal and service adapter. The caller supplies an immutable operation ID,
// current overlap identity, actual before/after leaf IDs and service fingerprint.
// It does not publish/acknowledge trust or waive offline-device admission.
// No public CLI invokes it until preparation cancellation and full recovery
// acceptance are available.
func RunBoundRelayAuthorityTransition(ctx context.Context, o RelayAuthoritySnapshotOptions, project, composeFile string) (relayauthority.TransitionState, error) {
	var state relayauthority.TransitionState
	if os.Geteuid() != 0 || ctx.Err() != nil || !o.Request.Valid() || !relayTrustDigest.MatchString(o.ServiceFingerprint) || !filepath.IsAbs(o.Directory) || filepath.Clean(o.Directory) != o.Directory {
		return state, ErrRelayAuthority
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	expected := ""
	intent := filepath.Join(o.Directory, "authority-transitions", o.Request.ID, "intent.json")
	if _, err := os.Lstat(intent); err == nil {
		// Readiness may be interrupted after the pinned intent was persisted. The
		// engine independently verifies canonical intent/state before any mutation.
		expected = o.ServiceFingerprint
	} else if !os.IsNotExist(err) || CheckFiles(o.Directory) != nil {
		return state, ErrRelayAuthority
	}
	service, err := BindRelayAuthorityService(ctx, o.Directory, project, composeFile, expected)
	if err != nil || service.Fingerprint() != o.ServiceFingerprint {
		return state, ErrRelayAuthority
	}
	if expected == "" {
		ca, err := authorityRead(filepath.Join(o.Directory, "secrets/issuer/ca.pem"), 0, 32768)
		if err != nil {
			return state, ErrRelayAuthority
		}
		observed, err := service.Observe(ctx, ca)
		if err != nil || observed != o.Request.PreviousLeaf {
			return state, ErrRelayAuthority
		}
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
	return (relayauthority.Transition{Directory: o.Directory, ServerName: service.binding.Config.ConsoleHost, Request: o.Request, Host: host, Trust: publisher}).Run(ctx)
}

// ResumeBoundRelayAuthorityTransition reloads the immutable request/options from
// protected snapshot metadata. A mixed live deployment must never be used to
// derive a different original leaf, authority or operation identity on restart.
func ResumeBoundRelayAuthorityTransition(ctx context.Context, directory, operationID, project, composeFile string) (relayauthority.TransitionState, error) {
	var state relayauthority.TransitionState
	if os.Geteuid() != 0 || ctx.Err() != nil || !authorityOperationID.MatchString(operationID) || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return state, ErrRelayAuthority
	}
	operation := filepath.Join(directory, "authority-transitions", operationID)
	raw, err := authorityRead(filepath.Join(operation, "snapshot.json"), 0, 1048576)
	var snapshot authoritySnapshot
	if err != nil || json.Unmarshal(raw, &snapshot) != nil || !bytes.Equal(raw, authorityJSON(snapshot)) || snapshot.Version != 1 || snapshot.Options.Directory != directory || snapshot.Options.Request.ID != operationID || !snapshot.Options.Request.Valid() {
		return state, ErrRelayAuthority
	}
	if _, err := verifyAuthoritySnapshot(operation, snapshot.Options); err != nil {
		return state, ErrRelayAuthority
	}
	return RunBoundRelayAuthorityTransition(ctx, snapshot.Options, project, composeFile)
}
