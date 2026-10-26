package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	authsaml "github.com/KazuhaHub/authcore/saml"
	"github.com/KazuhaHub/nethub/server/internal/providersecret"
	"github.com/KazuhaHub/nethub/server/internal/sso"
)

var _ sso.SAMLFlowRepository = (*ConsoleStore)(nil)

func (s *ConsoleStore) SAMLLoginProviders(ctx context.Context) ([]sso.Choice, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, true)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT p.slug,p.display_name FROM identity_providers p JOIN saml_providers s ON s.tenant_id=p.tenant_id AND s.id=p.id WHERE p.enabled AND p.deleted_at IS NULL ORDER BY p.slug`)
	if err != nil {
		return nil, err
	}
	choices := []sso.Choice{}
	for rows.Next() {
		p := sso.Choice{Protocol: "saml"}
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

func (s *ConsoleStore) samlLoginProvider(ctx context.Context, tx *sql.Tx, slug string, lock bool) (sso.SAMLLoginProvider, error) {
	query := `SELECT p.id,p.slug,p.display_name,p.revision,s.entity_id,s.metadata_xml,s.email_attribute,s.sp_key_enc FROM identity_providers p JOIN saml_providers s ON s.tenant_id=p.tenant_id AND s.id=p.id WHERE p.slug=$1 AND p.enabled AND p.deleted_at IS NULL`
	if lock {
		query += ` FOR SHARE OF p`
	}
	var p sso.SAMLLoginProvider
	var issuer, document string
	var sealed []byte
	if err := tx.QueryRowContext(ctx, query, slug).Scan(&p.ID, &p.Slug, &p.DisplayName, &p.Revision, &issuer, &document, &p.EmailAttribute, &sealed); err != nil {
		return sso.SAMLLoginProvider{}, sso.ErrFlow
	}
	bundle, err := s.ProviderSecrets.Open(providersecret.Binding{TenantID: s.Tenant, ProviderID: p.ID, Purpose: providersecret.SAMLSigningKey}, sealed)
	if err != nil {
		return sso.SAMLLoginProvider{}, sso.ErrFlow
	}
	defer clear(bundle)
	key, certificate, err := sso.ParseSAMLSigningIdentity(bundle)
	if err != nil {
		return sso.SAMLLoginProvider{}, sso.ErrFlow
	}
	metadata, err := sso.ParseSAMLMetadata([]byte(document), issuer)
	if err != nil {
		return sso.SAMLLoginProvider{}, sso.ErrFlow
	}
	p.Config = authsaml.Config{IDPMetadata: metadata, Key: key, Certificate: certificate, SignAuthnRequests: true, AllowEncryptedAssertions: true, ReplayCache: s.SAMLReplayCache(p.ID)}
	return p, nil
}

func (s *ConsoleStore) SAMLLoginProvider(ctx context.Context, slug string) (sso.SAMLLoginProvider, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, true)
	if err != nil {
		return sso.SAMLLoginProvider{}, err
	}
	defer tx.Rollback()
	p, err := s.samlLoginProvider(ctx, tx, slug, false)
	if err != nil {
		return sso.SAMLLoginProvider{}, err
	}
	return p, tx.Commit()
}

type samlPrivateState struct{ RequestID string }

func (s *ConsoleStore) SaveSAMLFlow(ctx context.Context, input sso.SAMLFlowInput) (time.Time, error) {
	state, err := sso.Digest(input.State)
	if err != nil || !sso.ValidSAMLRequestID(input.RequestID) || len(input.BrowserDigest) != 32 || len(input.InvitationDigest) != 0 && len(input.InvitationDigest) != 32 || input.Provider.Revision < 1 {
		return time.Time{}, sso.ErrFlow
	}
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
	err = tx.QueryRowContext(ctx, `SELECT revision FROM identity_providers WHERE id=$1 AND kind='saml' AND enabled AND deleted_at IS NULL FOR SHARE`, input.Provider.ID).Scan(&revision)
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
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, s.Tenant+":saml-flows"); err != nil {
		return time.Time{}, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM saml_flows WHERE expires_at<=clock_timestamp()`); err != nil {
		return time.Time{}, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM saml_flows`).Scan(&count); err != nil || count >= 10000 {
		return time.Time{}, sso.ErrFlow
	}
	var id string
	if err = tx.QueryRowContext(ctx, `SELECT gen_random_uuid()`).Scan(&id); err != nil {
		return time.Time{}, err
	}
	private, err := json.Marshal(samlPrivateState{RequestID: input.RequestID})
	if err != nil {
		return time.Time{}, sso.ErrFlow
	}
	defer clear(private)
	sealed, err := s.ProviderSecrets.Seal(providersecret.Binding{TenantID: s.Tenant, ProviderID: id, Purpose: providersecret.SAMLFlowState}, private)
	if err != nil {
		return time.Time{}, sso.ErrFlow
	}
	var expires time.Time
	err = tx.QueryRowContext(ctx, `WITH stamp AS (SELECT clock_timestamp() AS now) INSERT INTO saml_flows(id,tenant_id,provider_id,provider_revision,state_hash,browser_hash,invitation_hash,protocol_state_enc,created_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,stamp.now,stamp.now+interval '5 minutes' FROM stamp RETURNING expires_at`, id, s.Tenant, input.Provider.ID, revision, state, input.BrowserDigest, input.InvitationDigest, sealed).Scan(&expires)
	if err != nil {
		return time.Time{}, err
	}
	return expires, tx.Commit()
}

func (s *ConsoleStore) ConsumeSAMLFlow(ctx context.Context, slug, state string, browser []byte) (sso.ConsumedSAMLFlow, error) {
	digest, err := sso.Digest(state)
	if err != nil || len(browser) != 32 {
		return sso.ConsumedSAMLFlow{}, sso.ErrFlow
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return sso.ConsumedSAMLFlow{}, err
	}
	defer tx.Rollback()
	var id string
	err = tx.QueryRowContext(ctx, `SELECT f.id FROM saml_flows f JOIN identity_providers p ON p.tenant_id=f.tenant_id AND p.id=f.provider_id WHERE f.state_hash=$1 AND f.browser_hash=$2 AND p.slug=$3 AND f.consumed_at IS NULL AND f.expires_at>clock_timestamp()`, digest, browser, slug).Scan(&id)
	if err != nil {
		return sso.ConsumedSAMLFlow{}, sso.ErrFlow
	}
	p, err := s.samlLoginProvider(ctx, tx, slug, true)
	if err != nil {
		return sso.ConsumedSAMLFlow{}, sso.ErrFlow
	}
	var revision int64
	var sealed []byte
	err = tx.QueryRowContext(ctx, `SELECT provider_revision,protocol_state_enc FROM saml_flows WHERE id=$1 AND state_hash=$2 AND browser_hash=$3 AND provider_id=$4 FOR UPDATE`, id, digest, browser, p.ID).Scan(&revision, &sealed)
	if err != nil || revision != p.Revision {
		return sso.ConsumedSAMLFlow{}, sso.ErrFlow
	}
	private, err := s.ProviderSecrets.Open(providersecret.Binding{TenantID: s.Tenant, ProviderID: id, Purpose: providersecret.SAMLFlowState}, sealed)
	if err != nil {
		return sso.ConsumedSAMLFlow{}, sso.ErrFlow
	}
	defer clear(private)
	var restored samlPrivateState
	if json.Unmarshal(private, &restored) != nil || !sso.ValidSAMLRequestID(restored.RequestID) {
		return sso.ConsumedSAMLFlow{}, sso.ErrFlow
	}
	var consumed string
	err = tx.QueryRowContext(ctx, `UPDATE saml_flows SET consumed_at=clock_timestamp(),protocol_state_enc=NULL WHERE id=$1 AND consumed_at IS NULL AND created_at<=clock_timestamp() AND expires_at>clock_timestamp() RETURNING id`, id).Scan(&consumed)
	if err != nil {
		return sso.ConsumedSAMLFlow{}, sso.ErrFlow
	}
	return sso.ConsumedSAMLFlow{ID: id, RequestID: restored.RequestID, Provider: p}, tx.Commit()
}
