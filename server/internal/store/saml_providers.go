package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/netip"
	"time"

	authsaml "github.com/KazuhaHub/authcore/saml"
	"github.com/KazuhaHub/nethub/server/internal/providersecret"
	"github.com/KazuhaHub/nethub/server/internal/sso"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"github.com/jackc/pgx/v5/pgconn"
)

var _ web.SAMLProviderRepository = (*ConsoleStore)(nil)

// SAMLMetadata publishes only SP public material, including while disabled so an
// administrator can register the SP before enabling sign-in. Deleted slugs stay
// tombstoned. Reading metadata neither rotates keys nor creates browser state.
func (s *ConsoleStore) SAMLMetadata(ctx context.Context, slug, entityID, acs string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, true)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var id, issuer, document string
	var sealed []byte
	err = tx.QueryRowContext(ctx, `SELECT p.id,s.entity_id,s.metadata_xml,s.sp_key_enc FROM identity_providers p JOIN saml_providers s ON s.tenant_id=p.tenant_id AND s.id=p.id WHERE p.slug=$1 AND p.deleted_at IS NULL`, slug).Scan(&id, &issuer, &document, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, web.ErrSAMLNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	bundle, err := s.ProviderSecrets.Open(providersecret.Binding{TenantID: s.Tenant, ProviderID: id, Purpose: providersecret.SAMLSigningKey}, sealed)
	if err != nil {
		return nil, web.ErrSAMLMetadata
	}
	defer clear(bundle)
	key, certificate, err := sso.ParseSAMLSigningIdentity(bundle)
	if err != nil {
		return nil, web.ErrSAMLMetadata
	}
	metadata, err := sso.ParseSAMLMetadata([]byte(document), issuer)
	if err != nil {
		return nil, web.ErrSAMLMetadata
	}
	provider, err := sso.NewSAMLProvider(authsaml.Config{EntityID: entityID, ACSURL: acs, IDPMetadata: metadata, Key: key, Certificate: certificate, SignAuthnRequests: true, AllowEncryptedAssertions: true, ReplayCache: s.SAMLReplayCache(id)})
	if err != nil {
		return nil, web.ErrSAMLMetadata
	}
	public, err := provider.MetadataXML()
	if err != nil {
		return nil, web.ErrSAMLMetadata
	}
	return public, nil
}

type samlSnapshot struct {
	Provider web.SAMLProvider
	Revision int64
	Metadata string
	Key      []byte
}

const samlProjection = `p.id,p.slug,p.display_name,p.enabled,p.created_at,s.entity_id,s.email_attribute,s.sp_key_enc IS NOT NULL`

func scanSAML(row interface{ Scan(...any) error }) (web.SAMLProvider, error) {
	var p web.SAMLProvider
	err := row.Scan(&p.ID, &p.Slug, &p.DisplayName, &p.Enabled, &p.CreatedAt, &p.EntityID, &p.EmailAttribute, &p.HasSigningKey)
	if errors.Is(err, sql.ErrNoRows) {
		err = web.ErrSAMLNotFound
	}
	return p, err
}

func (s *ConsoleStore) SAMLProviders(ctx context.Context, actor string, query web.UserQuery) (web.SAMLProviderPage, error) {
	if query.Limit < 1 || query.Limit > 200 {
		return web.SAMLProviderPage{}, web.ErrProviderInput
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.SAMLProviderPage{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return web.SAMLProviderPage{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+samlProjection+` FROM identity_providers p JOIN saml_providers s ON s.tenant_id=p.tenant_id AND s.id=p.id WHERE p.deleted_at IS NULL AND (nullif($1,'')::uuid IS NULL OR p.id>nullif($1,'')::uuid) ORDER BY p.id LIMIT $2`, query.AfterID, query.Limit+1)
	if err != nil {
		return web.SAMLProviderPage{}, err
	}
	page := web.SAMLProviderPage{Items: []web.SAMLProvider{}}
	for rows.Next() {
		p, e := scanSAML(rows)
		if e != nil {
			rows.Close()
			return web.SAMLProviderPage{}, e
		}
		page.Items = append(page.Items, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return web.SAMLProviderPage{}, err
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		cursor := base64.RawURLEncoding.EncodeToString([]byte(page.Items[len(page.Items)-1].ID))
		page.NextCursor = &cursor
	}
	return page, tx.Commit()
}

func (s *ConsoleStore) samlPreflight(ctx context.Context, actor, id string) (samlSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return samlSnapshot{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return samlSnapshot{}, err
	}
	var snapshot samlSnapshot
	if id != "" {
		p := &snapshot.Provider
		err = tx.QueryRowContext(ctx, `SELECT `+samlProjection+`,p.revision,s.metadata_xml,s.sp_key_enc FROM identity_providers p JOIN saml_providers s ON s.tenant_id=p.tenant_id AND s.id=p.id WHERE p.id=$1 AND p.deleted_at IS NULL`, id).Scan(&p.ID, &p.Slug, &p.DisplayName, &p.Enabled, &p.CreatedAt, &p.EntityID, &p.EmailAttribute, &p.HasSigningKey, &snapshot.Revision, &snapshot.Metadata, &snapshot.Key)
		if errors.Is(err, sql.ErrNoRows) {
			return samlSnapshot{}, web.ErrSAMLNotFound
		}
		if err != nil {
			return samlSnapshot{}, err
		}
	}
	return snapshot, tx.Commit()
}

func (s *ConsoleStore) validateSAML(ctx context.Context, input web.SAMLProviderInput) error {
	if s.ProviderSecrets == nil || s.ValidateSAML == nil {
		return web.ErrSAMLMetadata
	}
	metadata, err := sso.ParseSAMLMetadata([]byte(input.MetadataXML), input.EntityID)
	if err != nil || !metadata.ValidUntil.IsZero() && !time.Now().Before(metadata.ValidUntil) {
		return web.ErrSAMLMetadata
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err = s.ValidateSAML(ctx, input); err != nil || ctx.Err() != nil {
		return web.ErrSAMLMetadata
	}
	return nil
}

func (s *ConsoleStore) CreateSAMLProvider(ctx context.Context, actor string, input web.SAMLProviderInput, ip netip.Addr) (web.SAMLProvider, error) {
	input, err := web.NormalizeSAMLInput(input)
	if err != nil || !ip.IsValid() || ip.Zone() != "" {
		return web.SAMLProvider{}, web.ErrProviderInput
	}
	if _, err = s.samlPreflight(ctx, actor, ""); err != nil {
		return web.SAMLProvider{}, err
	}
	if err = s.validateSAML(ctx, input); err != nil {
		return web.SAMLProvider{}, err
	}
	// Generate the signing identity before the short final database transaction.
	key, err := sso.NewSAMLSigningIdentity(time.Now())
	if err != nil {
		return web.SAMLProvider{}, err
	}
	defer clear(key)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.SAMLProvider{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return web.SAMLProvider{}, err
	}
	var id string
	err = tx.QueryRowContext(ctx, `INSERT INTO identity_providers(tenant_id,kind,slug,display_name,enabled) VALUES($1,'saml',$2,$3,$4) RETURNING id`, s.Tenant, input.Slug, input.DisplayName, input.Enabled).Scan(&id)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return web.SAMLProvider{}, web.ErrProviderSlugTaken
		}
		return web.SAMLProvider{}, err
	}
	sealed, err := s.ProviderSecrets.Seal(providersecret.Binding{TenantID: s.Tenant, ProviderID: id, Purpose: providersecret.SAMLSigningKey}, key)
	if err != nil {
		return web.SAMLProvider{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO saml_providers(id,tenant_id,entity_id,metadata_xml,email_attribute,sp_key_enc) VALUES($1,$2,$3,$4,$5,$6)`, id, s.Tenant, input.EntityID, input.MetadataXML, input.EmailAttribute, sealed); err != nil {
		return web.SAMLProvider{}, err
	}
	if err = providerAudit(ctx, tx, actor, "saml_provider.created", id, ip); err != nil {
		return web.SAMLProvider{}, err
	}
	p, err := scanSAML(tx.QueryRowContext(ctx, `SELECT `+samlProjection+` FROM identity_providers p JOIN saml_providers s ON s.tenant_id=p.tenant_id AND s.id=p.id WHERE p.id=$1`, id))
	if err != nil {
		return web.SAMLProvider{}, err
	}
	return p, tx.Commit()
}

func (s *ConsoleStore) UpdateSAMLProvider(ctx context.Context, actor, id string, patch web.SAMLProviderPatch, ip netip.Addr) (web.SAMLProvider, error) {
	if !ip.IsValid() || ip.Zone() != "" || patch.DisplayName == nil && patch.EntityID == nil && patch.MetadataXML == nil && patch.EmailAttribute == nil && patch.Enabled == nil {
		return web.SAMLProvider{}, web.ErrProviderInput
	}
	before, err := s.samlPreflight(ctx, actor, id)
	if err != nil {
		return web.SAMLProvider{}, err
	}
	p := before.Provider
	input := web.SAMLProviderInput{Slug: p.Slug, DisplayName: p.DisplayName, EntityID: p.EntityID, MetadataXML: before.Metadata, EmailAttribute: p.EmailAttribute, Enabled: p.Enabled}
	if patch.DisplayName != nil {
		input.DisplayName = *patch.DisplayName
	}
	if patch.EntityID != nil {
		input.EntityID = *patch.EntityID
	}
	if patch.MetadataXML != nil {
		input.MetadataXML = *patch.MetadataXML
	}
	if patch.EmailAttribute != nil {
		input.EmailAttribute = *patch.EmailAttribute
	}
	if patch.Enabled != nil {
		input.Enabled = *patch.Enabled
	}
	input, err = web.NormalizeSAMLInput(input)
	if err != nil {
		return web.SAMLProvider{}, err
	}
	if patch.EntityID != nil || patch.MetadataXML != nil || !p.Enabled && input.Enabled {
		if len(before.Key) == 0 {
			return web.SAMLProvider{}, web.ErrSAMLMetadata
		}
		if err = s.validateSAML(ctx, input); err != nil {
			return web.SAMLProvider{}, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.SAMLProvider{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return web.SAMLProvider{}, err
	}
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM identity_providers WHERE id=$1 AND kind='saml' AND deleted_at IS NULL FOR UPDATE`, id).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return web.SAMLProvider{}, web.ErrSAMLNotFound
	}
	if err != nil {
		return web.SAMLProvider{}, err
	}
	if revision != before.Revision {
		return web.SAMLProvider{}, web.ErrProviderChanged
	}
	if input.EntityID != p.EntityID {
		var bound bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM user_identities WHERE provider_id=$1)`, id).Scan(&bound); err != nil {
			return web.SAMLProvider{}, err
		}
		if bound {
			return web.SAMLProvider{}, web.ErrProviderInUse
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE identity_providers SET display_name=$2,enabled=$3,revision=revision+1 WHERE id=$1`, id, input.DisplayName, input.Enabled); err != nil {
		return web.SAMLProvider{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE saml_providers SET entity_id=$2,metadata_xml=$3,email_attribute=$4 WHERE id=$1`, id, input.EntityID, input.MetadataXML, input.EmailAttribute); err != nil {
		return web.SAMLProvider{}, err
	}
	if err = providerAudit(ctx, tx, actor, "saml_provider.updated", id, ip); err != nil {
		return web.SAMLProvider{}, err
	}
	p, err = scanSAML(tx.QueryRowContext(ctx, `SELECT `+samlProjection+` FROM identity_providers p JOIN saml_providers s ON s.tenant_id=p.tenant_id AND s.id=p.id WHERE p.id=$1`, id))
	if err != nil {
		return web.SAMLProvider{}, err
	}
	return p, tx.Commit()
}

func (s *ConsoleStore) DeleteSAMLProvider(ctx context.Context, actor, id string, ip netip.Addr) error {
	if !ip.IsValid() || ip.Zone() != "" {
		return web.ErrProviderInput
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return err
	}
	var provider string
	err = tx.QueryRowContext(ctx, `SELECT id FROM identity_providers WHERE id=$1 AND kind='saml' AND deleted_at IS NULL FOR UPDATE`, id).Scan(&provider)
	if errors.Is(err, sql.ErrNoRows) {
		return web.ErrSAMLNotFound
	}
	if err != nil {
		return err
	}
	var bound bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM user_identities WHERE provider_id=$1)`, id).Scan(&bound); err != nil {
		return err
	}
	if bound {
		return web.ErrProviderInUse
	}
	if _, err = tx.ExecContext(ctx, `UPDATE invites SET cancelled_at=coalesce(cancelled_at,clock_timestamp()) WHERE provider_id=$1 AND used_at IS NULL`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE saml_providers SET sp_key_enc=NULL WHERE id=$1`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE identity_providers SET enabled=false,deleted_at=clock_timestamp(),revision=revision+1 WHERE id=$1`, id); err != nil {
		return err
	}
	if err = providerAudit(ctx, tx, actor, "saml_provider.deleted", id, ip); err != nil {
		return err
	}
	return tx.Commit()
}
