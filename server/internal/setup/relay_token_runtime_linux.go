package setup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/claim"
	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/KazuhaHub/nethub/server/internal/relayprobe"
	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

// The protected command must hold relay-operation.lock and admit this exact
// retained operation before constructing a host. No HTTP handler exposes it.
type relayTokenRuntimeHost struct {
	options  relayTokenMaterialOptions
	service  *BoundRelayAuthorityService
	baseline string
}

var _ relaytoken.Host = (*relayTokenRuntimeHost)(nil)

func (h *relayTokenRuntimeHost) bound() bool {
	return h != nil && h.service != nil && h.options.Request.Valid() &&
		relayTrustDigest.MatchString(h.baseline) &&
		h.options.Request.Binding == h.service.Fingerprint() && h.options.Directory == h.service.binding.Directory
}

func (h *relayTokenRuntimeHost) Prepare(ctx context.Context, request relaytoken.Request) (relaytoken.Snapshot, error) {
	if !h.bound() || request != h.options.Request {
		return relaytoken.Snapshot{}, relaytoken.ErrTransition
	}
	prepared, err := prepareRelayTokenMaterial(ctx, h.options)
	baseline, baselineErr := snapshotRelayTokenBaseline(ctx, h.options)
	if err != nil || baselineErr != nil || baseline != h.baseline {
		return relaytoken.Snapshot{}, relaytoken.ErrTransition
	}
	return prepared, nil
}

func (h *relayTokenRuntimeHost) VerifySnapshot(ctx context.Context, intent relaytoken.Intent) error {
	if !h.bound() || !intent.Valid() || intent.Request != h.options.Request {
		return relaytoken.ErrTransition
	}
	verified, err := verifyRelayTokenMaterial(ctx, h.options)
	baseline, baselineErr := snapshotRelayTokenBaseline(ctx, h.options)
	if err != nil || verified != intent.Snapshot || baselineErr != nil || baseline != h.baseline {
		return relaytoken.ErrTransition
	}
	return nil
}

func (h *relayTokenRuntimeHost) Publish(ctx context.Context, intent relaytoken.Intent) error {
	if !h.bound() {
		return relaytoken.ErrTransition
	}
	return publishRelayTokenMaterial(ctx, h.options, intent)
}

// published requires the durable phase, the original backup and every exact
// candidate live byte. It does not waive ordinary host admission globally.
func (h *relayTokenRuntimeHost) published(ctx context.Context, intent relaytoken.Intent, phases ...string) error {
	if h.VerifySnapshot(ctx, intent) != nil {
		return relaytoken.ErrTransition
	}
	operation := filepath.Join(h.options.Directory, "token-transitions", intent.Request.OperationID)
	journal := relayTokenJournal{directory: operation, request: intent.Request}
	saved, err := journal.ReadIntent(ctx)
	state, stateErr := journal.ReadState(ctx)
	if err != nil || saved != intent || stateErr != nil || !slices.Contains(phases, state.Phase) {
		return relaytoken.ErrTransition
	}
	raw, err := authorityRead(filepath.Join(operation, "snapshot.json"), 0, 1048576)
	var snapshot relayTokenMaterial
	if err != nil || json.Unmarshal(raw, &snapshot) != nil || authorityHash(raw) != intent.Snapshot.Digest {
		return relaytoken.ErrTransition
	}
	for _, file := range snapshot.Files {
		current, err := authorityRead(filepath.Join(h.options.Directory, filepath.FromSlash(file.Path)), file.UID, 32768)
		if ctx.Err() != nil || err != nil || authorityHash(current) != file.After {
			return relaytoken.ErrTransition
		}
	}
	maintenance, present, err := authorityTree(filepath.Join(h.options.Directory, "secrets/issuer/maintenance"))
	if err != nil || present != snapshot.MaintenancePresent || !bytes.Equal(authorityJSON(maintenance), authorityJSON(snapshot.Maintenance)) {
		return relaytoken.ErrTransition
	}
	return nil
}

func (h *relayTokenRuntimeHost) Reload(ctx context.Context, intent relaytoken.Intent) error {
	bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if h.published(bounded, intent, "reloading") != nil || h.service.check(bounded, false, false) != nil ||
		checkRelayFiles(h.options.Directory, h.service.binding.Config, true) != nil {
		return relaytoken.ErrTransition
	}
	ca, err := authorityRead(filepath.Join(h.options.Directory, "runtime/trust/relay-ca.pem"), 65532, 32768)
	if err != nil || h.service.reloadBound(bounded, ca) != nil {
		return relaytoken.ErrTransition
	}
	return nil
}

func (h *relayTokenRuntimeHost) Verify(ctx context.Context, intent relaytoken.Intent) error {
	bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if h.published(bounded, intent, "verifying", "complete") != nil ||
		checkRelayFiles(h.options.Directory, h.service.binding.Config, true) != nil {
		return relaytoken.ErrTransition
	}
	ca, err := authorityRead(filepath.Join(h.options.Directory, "runtime/trust/relay-ca.pem"), 65532, 32768)
	leaf, leafErr := authorityRead(filepath.Join(h.options.Directory, "runtime/relay/relay-cert.pem"), 65532, 32768)
	if err != nil || leafErr != nil {
		return relaytoken.ErrTransition
	}
	observed, err := h.service.Observe(bounded, ca)
	if err != nil || observed != authorityLeaf(leaf) {
		return relaytoken.ErrTransition
	}
	credential, err := h.probeCredential(bounded)
	if err != nil {
		return relaytoken.ErrTransition
	}
	operation := filepath.Join(h.options.Directory, "token-transitions", intent.Request.OperationID)
	for _, side := range []string{"after", "before", "after"} {
		token, err := authorityRead(filepath.Join(operation, "snapshot", side, "secrets/authz/frp_token"), 0, 65)
		if err != nil || len(token) != 65 || token[64] != '\n' {
			return relaytoken.ErrTransition
		}
		credential.Token = string(token[:64])
		accepted, err := relayprobe.LoginToken(bounded, "127.0.0.1:7000", h.service.binding.Config.ConsoleHost, ca, credential)
		if err != nil || accepted != (side == "after") {
			return relaytoken.ErrTransition
		}
	}
	if h.published(bounded, intent, "verifying", "complete") != nil || h.service.check(bounded, true, true) != nil {
		return relaytoken.ErrTransition
	}
	return nil
}

// probeCredential reads one existing unrevoked identity without modifying its claim
// floor, credential hash, grants or audits. The claim stays in private memory.
// No available identity is a refusal, never permission to create a fixture row.
func (h *relayTokenRuntimeHost) probeCredential(ctx context.Context) (relayprobe.LoginCredential, error) {
	empty := relayprobe.LoginCredential{}
	if !h.bound() {
		return empty, relaytoken.ErrTransition
	}
	binding, err := h.service.host.database(ctx)
	if err != nil {
		return empty, relaytoken.ErrTransition
	}
	run, err := guiissuer.NewDockerSQLRunner(binding)
	if err != nil {
		return empty, relaytoken.ErrTransition
	}
	raw, err := run(ctx, []byte(`BEGIN READ ONLY;
SET LOCAL statement_timeout='2000ms';
SELECT coalesce((SELECT json_build_object('device_id',id,'tenant_id',tenant_id,'subdomain',subdomain,
 'issued_at',to_char(domain_claim_issued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
 FROM devices WHERE NOT revoked ORDER BY id LIMIT 1),'null'::json);
ROLLBACK;
`))
	var identity struct {
		DeviceID  string `json:"device_id"`
		TenantID  string `json:"tenant_id"`
		Subdomain string `json:"subdomain"`
		IssuedAt  string `json:"issued_at"`
	}
	if err != nil || len(raw) > 4096 || json.Unmarshal(bytes.TrimSpace(raw), &identity) != nil {
		return empty, relaytoken.ErrTransition
	}
	issued, err := time.Parse("2006-01-02T15:04:05.000000Z", identity.IssuedAt)
	key, keyErr := authorityRead(filepath.Join(h.options.Directory, "secrets/authz/claim_key"), 65532, 65)
	if err != nil || issued.Format("2006-01-02T15:04:05.000000Z") != identity.IssuedAt || keyErr != nil || len(key) != 65 || key[64] != '\n' {
		return empty, relaytoken.ErrTransition
	}
	decoded, err := hex.DecodeString(strings.TrimSuffix(string(key), "\n"))
	if err != nil || len(decoded) != 32 {
		return empty, relaytoken.ErrTransition
	}
	signer, err := claim.New(claim.InitialKeyID, map[string][]byte{claim.InitialKeyID: decoded})
	if err != nil {
		return empty, relaytoken.ErrTransition
	}
	encoded, err := signer.Issue(identity.DeviceID, identity.Subdomain, identity.TenantID, issued)
	if err != nil {
		return empty, relaytoken.ErrTransition
	}
	return relayprobe.LoginCredential{DeviceID: identity.DeviceID, DomainClaim: encoded}, nil
}
