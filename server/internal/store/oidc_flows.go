package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	authoidc "github.com/KazuhaHub/authcore/oidc"
	"github.com/KazuhaHub/nethub/server/internal/providersecret"
	"github.com/KazuhaHub/nethub/server/internal/sso"
)

var _ sso.FlowRepository = (*ConsoleStore)(nil)

func (s *ConsoleStore) LoginProviders(ctx context.Context) ([]sso.Choice, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, true)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT p.slug,p.display_name FROM identity_providers p JOIN oidc_providers o ON o.tenant_id=p.tenant_id AND o.id=p.id WHERE p.enabled AND p.deleted_at IS NULL ORDER BY p.slug`)
	if err != nil {
		return nil, err
	}
	choices := []sso.Choice{}
	for rows.Next() {
		var p sso.Choice
		if err = rows.Scan(&p.Slug, &p.DisplayName); err != nil {
			rows.Close()
			return nil, err
		}
		choices = append(choices, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return choices, tx.Commit()
}

func (s *ConsoleStore) loginProvider(ctx context.Context, tx *sql.Tx, slug string, lock bool) (sso.LoginProvider, error) {
	query := `SELECT ` + oidcProjection + ` FROM identity_providers p JOIN oidc_providers o ON o.tenant_id=p.tenant_id AND o.id=p.id WHERE p.slug=$1 AND p.enabled AND p.deleted_at IS NULL`
	if lock {
		query += ` FOR SHARE OF p`
	}
	row, err := scanOIDC(tx.QueryRowContext(ctx, query, slug))
	if err != nil {
		return sso.LoginProvider{}, sso.ErrFlow
	}
	p := row.Provider
	config := authoidc.Config{IssuerURL: p.IssuerURL, ClientID: p.ClientID, Scopes: p.Scopes}
	if len(row.Secret) != 0 {
		plaintext, err := s.ProviderSecrets.Open(providersecret.Binding{TenantID: s.Tenant, ProviderID: p.ID, Purpose: providersecret.OIDCClientSecret}, row.Secret)
		if err != nil {
			return sso.LoginProvider{}, sso.ErrFlow
		}
		config.ClientSecret = string(plaintext)
		clear(plaintext)
	}
	return sso.LoginProvider{ID: p.ID, Slug: p.Slug, DisplayName: p.DisplayName, Revision: row.Revision, Config: config}, nil
}

func (s *ConsoleStore) LoginProvider(ctx context.Context, slug string) (sso.LoginProvider, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, true)
	if err != nil {
		return sso.LoginProvider{}, err
	}
	defer tx.Rollback()
	p, err := s.loginProvider(ctx, tx, slug, false)
	if err != nil {
		return sso.LoginProvider{}, err
	}
	return p, tx.Commit()
}

// The encrypted payload excludes the raw state bearer. Binding and expiry are
// authoritative columns; only these three private protocol values are restored.
type oidcPrivateState struct{ Nonce, Verifier, Configuration string }

func (s *ConsoleStore) SaveOIDCFlow(ctx context.Context, input sso.FlowInput) (time.Time, error) {
	if !sso.ValidState(input.State) || len(input.BrowserDigest) != 32 || len(input.InvitationDigest) != 0 && len(input.InvitationDigest) != 32 || input.Provider.Revision < 1 {
		return time.Time{}, sso.ErrFlow
	}
	stateHash, _ := sso.Digest(input.State.Value)
	if len(input.InvitationDigest) == 0 {
		input.InvitationDigest = nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM identity_providers WHERE id=$1 AND kind='oidc' AND enabled AND deleted_at IS NULL FOR SHARE`, input.Provider.ID).Scan(&revision)
	if err != nil || revision != input.Provider.Revision {
		return time.Time{}, sso.ErrFlow
	}
	if len(input.InvitationDigest) != 0 {
		var valid bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM invites WHERE token_hash=$1 AND (provider_id IS NULL OR provider_id=$2) AND used_at IS NULL AND cancelled_at IS NULL AND created_at<=clock_timestamp() AND expires_at>clock_timestamp())`, input.InvitationDigest, input.Provider.ID).Scan(&valid)
		if err != nil || !valid {
			return time.Time{}, sso.ErrFlow
		}
	}
	// Serialize only short flow insertion/cleanup, never remote I/O. This bounds
	// anonymous pending state even across multiple Web processes.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, s.Tenant+":oidc-flows"); err != nil {
		return time.Time{}, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM oidc_flows WHERE expires_at<=clock_timestamp()`); err != nil {
		return time.Time{}, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM oidc_flows`).Scan(&count); err != nil || count >= 10000 {
		return time.Time{}, sso.ErrFlow
	}
	var id string
	if err = tx.QueryRowContext(ctx, `SELECT gen_random_uuid()`).Scan(&id); err != nil {
		return time.Time{}, err
	}
	payload, err := json.Marshal(oidcPrivateState{input.State.Nonce, input.State.Verifier, input.State.Configuration})
	if err != nil {
		return time.Time{}, sso.ErrFlow
	}
	defer clear(payload)
	encrypted, err := s.ProviderSecrets.Seal(providersecret.Binding{TenantID: s.Tenant, ProviderID: id, Purpose: providersecret.OIDCFlowState}, payload)
	if err != nil {
		return time.Time{}, sso.ErrFlow
	}
	var expires time.Time
	err = tx.QueryRowContext(ctx, `WITH stamp AS (SELECT clock_timestamp() AS now) INSERT INTO oidc_flows(id,tenant_id,provider_id,provider_revision,state_hash,browser_hash,invitation_hash,protocol_state_enc,created_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,stamp.now,stamp.now+interval '5 minutes' FROM stamp RETURNING expires_at`, id, s.Tenant, input.Provider.ID, revision, stateHash, input.BrowserDigest, input.InvitationDigest, encrypted).Scan(&expires)
	if err != nil {
		return time.Time{}, err
	}
	return expires, tx.Commit()
}

func (s *ConsoleStore) ConsumeOIDCFlow(ctx context.Context, slug, state string, browserHash []byte) (sso.ConsumedFlow, error) {
	stateHash, err := sso.Digest(state)
	if err != nil || len(browserHash) != 32 {
		return sso.ConsumedFlow{}, sso.ErrFlow
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return sso.ConsumedFlow{}, err
	}
	defer tx.Rollback()
	// The preliminary lookup does not lock a flow before its provider. A random
	// browser cookie cannot decrypt configuration or consume a legitimate flow.
	var id string
	err = tx.QueryRowContext(ctx, `SELECT f.id FROM oidc_flows f JOIN identity_providers p ON p.tenant_id=f.tenant_id AND p.id=f.provider_id WHERE f.state_hash=$1 AND f.browser_hash=$2 AND p.slug=$3 AND f.consumed_at IS NULL AND f.expires_at>clock_timestamp()`, stateHash, browserHash, slug).Scan(&id)
	if err != nil {
		return sso.ConsumedFlow{}, sso.ErrFlow
	}
	p, err := s.loginProvider(ctx, tx, slug, true)
	if err != nil {
		return sso.ConsumedFlow{}, sso.ErrFlow
	}
	var revision int64
	var payload []byte
	err = tx.QueryRowContext(ctx, `SELECT provider_revision,protocol_state_enc FROM oidc_flows WHERE id=$1 AND state_hash=$2 AND browser_hash=$3 AND provider_id=$4 FOR UPDATE`, id, stateHash, browserHash, p.ID).Scan(&revision, &payload)
	if err != nil || revision != p.Revision {
		return sso.ConsumedFlow{}, sso.ErrFlow
	}
	plaintext, err := s.ProviderSecrets.Open(providersecret.Binding{TenantID: s.Tenant, ProviderID: id, Purpose: providersecret.OIDCFlowState}, payload)
	if err != nil {
		return sso.ConsumedFlow{}, sso.ErrFlow
	}
	defer clear(plaintext)
	var private oidcPrivateState
	if json.Unmarshal(plaintext, &private) != nil {
		return sso.ConsumedFlow{}, sso.ErrFlow
	}
	restored := authoidc.State{Value: state, Nonce: private.Nonce, Verifier: private.Verifier, Configuration: private.Configuration}
	if !sso.ValidState(restored) {
		return sso.ConsumedFlow{}, sso.ErrFlow
	}
	var consumed string
	err = tx.QueryRowContext(ctx, `UPDATE oidc_flows SET consumed_at=clock_timestamp(),protocol_state_enc=NULL WHERE id=$1 AND consumed_at IS NULL AND created_at<=clock_timestamp() AND expires_at>clock_timestamp() RETURNING id`, id).Scan(&consumed)
	if err != nil {
		return sso.ConsumedFlow{}, sso.ErrFlow
	}
	return sso.ConsumedFlow{ID: id, Provider: p, State: restored}, tx.Commit()
}

func (s *ConsoleStore) SSOFailed(ctx context.Context, ip netip.Addr, reason string) error {
	if !ip.IsValid() || ip.Zone() != "" || !sso.ValidFailureReason(reason) {
		return errors.New("invalid SSO audit")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	payload, _ := json.Marshal(map[string]string{"source_ip": ip.Unmap().String(), "reason": reason})
	if _, err = tx.ExecContext(ctx, `SELECT append_audit('system',NULL,'auth.sso_failed',NULL,$1::jsonb)`, string(payload)); err != nil {
		return err
	}
	return tx.Commit()
}
