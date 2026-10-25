package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/providersecret"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"github.com/jackc/pgx/v5/pgconn"
)

type oidcSnapshot struct {
	Provider web.OIDCProvider
	Revision int64
	Secret   []byte
}

const oidcProjection = `p.id,p.slug,p.display_name,p.enabled,p.created_at,p.revision,
 o.issuer_url,o.client_id,to_json(o.scopes),o.client_secret_enc`

func scanOIDC(row interface{ Scan(...any) error }) (oidcSnapshot, error) {
	var s oidcSnapshot
	var scopes []byte
	p := &s.Provider
	err := row.Scan(&p.ID, &p.Slug, &p.DisplayName, &p.Enabled, &p.CreatedAt, &s.Revision, &p.IssuerURL, &p.ClientID, &scopes, &s.Secret)
	if err == nil {
		err = json.Unmarshal(scopes, &p.Scopes)
		p.HasClientSecret = len(s.Secret) != 0
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = web.ErrOIDCNotFound
	}
	return s, err
}

func providerAudit(ctx context.Context, tx *sql.Tx, actor, action, id string, ip netip.Addr) error {
	if !ip.IsValid() || ip.Zone() != "" {
		return web.ErrProviderInput
	}
	metadata, _ := json.Marshal(map[string]string{"provider_id": id, "source_ip": ip.Unmap().String()})
	_, err := tx.ExecContext(ctx, `SELECT append_audit('user',$1,$2,NULL,$3::jsonb)`, actor, action, string(metadata))
	return err
}

func (s *ConsoleStore) OIDCProviders(ctx context.Context, actor string, query web.UserQuery) (web.OIDCProviderPage, error) {
	if query.Limit < 1 || query.Limit > 200 {
		return web.OIDCProviderPage{}, web.ErrProviderInput
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.OIDCProviderPage{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return web.OIDCProviderPage{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+oidcProjection+` FROM identity_providers p JOIN oidc_providers o ON o.tenant_id=p.tenant_id AND o.id=p.id WHERE p.deleted_at IS NULL AND (nullif($1,'')::uuid IS NULL OR p.id>nullif($1,'')::uuid) ORDER BY p.id LIMIT $2`, query.AfterID, query.Limit+1)
	if err != nil {
		return web.OIDCProviderPage{}, err
	}
	page := web.OIDCProviderPage{Items: []web.OIDCProvider{}}
	for rows.Next() {
		row, e := scanOIDC(rows)
		if e != nil {
			rows.Close()
			return web.OIDCProviderPage{}, e
		}
		page.Items = append(page.Items, row.Provider)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return web.OIDCProviderPage{}, err
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		cursor := base64.RawURLEncoding.EncodeToString([]byte(page.Items[len(page.Items)-1].ID))
		page.NextCursor = &cursor
	}
	return page, tx.Commit()
}

// The preflight transaction ends before any remote request. The final writer
// checks live authority again and compares the provider's revision under lock.
func (s *ConsoleStore) oidcPreflight(ctx context.Context, actor, id string) (oidcSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return oidcSnapshot{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return oidcSnapshot{}, err
	}
	var snapshot oidcSnapshot
	if id != "" {
		snapshot, err = scanOIDC(tx.QueryRowContext(ctx, `SELECT `+oidcProjection+` FROM identity_providers p JOIN oidc_providers o ON o.tenant_id=p.tenant_id AND o.id=p.id WHERE p.id=$1 AND p.deleted_at IS NULL`, id))
		if err != nil {
			return oidcSnapshot{}, err
		}
	}
	return snapshot, tx.Commit()
}

func (s *ConsoleStore) validateOIDC(ctx context.Context, input web.OIDCProviderInput) error {
	if s.ValidateOIDC == nil || s.ProviderSecrets == nil {
		return web.ErrOIDCDiscovery
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.ValidateOIDC(ctx, input); err != nil || ctx.Err() != nil {
		return web.ErrOIDCDiscovery
	}
	return nil
}

func (s *ConsoleStore) sealOIDC(id, secret string) ([]byte, error) {
	if secret == "" {
		return nil, nil
	}
	plaintext := []byte(secret)
	defer clear(plaintext)
	return s.ProviderSecrets.Seal(providersecret.Binding{TenantID: s.Tenant, ProviderID: id, Purpose: providersecret.OIDCClientSecret}, plaintext)
}

func (s *ConsoleStore) CreateOIDCProvider(ctx context.Context, actor string, input web.OIDCProviderInput, ip netip.Addr) (web.OIDCProvider, error) {
	input, err := web.NormalizeOIDCInput(input)
	if err != nil || !ip.IsValid() || ip.Zone() != "" {
		return web.OIDCProvider{}, web.ErrProviderInput
	}
	if _, err = s.oidcPreflight(ctx, actor, ""); err != nil {
		return web.OIDCProvider{}, err
	}
	if err = s.validateOIDC(ctx, input); err != nil {
		return web.OIDCProvider{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.OIDCProvider{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return web.OIDCProvider{}, err
	}
	var id string
	err = tx.QueryRowContext(ctx, `INSERT INTO identity_providers(tenant_id,kind,slug,display_name,enabled) VALUES($1,'oidc',$2,$3,$4) RETURNING id`, s.Tenant, input.Slug, input.DisplayName, input.Enabled).Scan(&id)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return web.OIDCProvider{}, web.ErrProviderSlugTaken
		}
		return web.OIDCProvider{}, err
	}
	secret, err := s.sealOIDC(id, input.ClientSecret)
	if err != nil {
		return web.OIDCProvider{}, err
	}
	scopes, _ := json.Marshal(input.Scopes)
	_, err = tx.ExecContext(ctx, `INSERT INTO oidc_providers(id,tenant_id,issuer_url,client_id,client_secret_enc,scopes) VALUES($1,$2,$3,$4,$5,ARRAY(SELECT jsonb_array_elements_text($6::jsonb)))`, id, s.Tenant, input.IssuerURL, input.ClientID, secret, string(scopes))
	if err != nil {
		return web.OIDCProvider{}, err
	}
	if err = providerAudit(ctx, tx, actor, "oidc_provider.created", id, ip); err != nil {
		return web.OIDCProvider{}, err
	}
	row, err := scanOIDC(tx.QueryRowContext(ctx, `SELECT `+oidcProjection+` FROM identity_providers p JOIN oidc_providers o ON o.tenant_id=p.tenant_id AND o.id=p.id WHERE p.id=$1`, id))
	if err != nil {
		return web.OIDCProvider{}, err
	}
	return row.Provider, tx.Commit()
}

func (s *ConsoleStore) UpdateOIDCProvider(ctx context.Context, actor, id string, patch web.OIDCProviderPatch, ip netip.Addr) (web.OIDCProvider, error) {
	if !ip.IsValid() || ip.Zone() != "" || patch.DisplayName == nil && patch.IssuerURL == nil && patch.ClientID == nil && patch.ClientSecret == nil && patch.Scopes == nil && patch.Enabled == nil {
		return web.OIDCProvider{}, web.ErrProviderInput
	}
	before, err := s.oidcPreflight(ctx, actor, id)
	if err != nil {
		return web.OIDCProvider{}, err
	}
	p := before.Provider
	input := web.OIDCProviderInput{Slug: p.Slug, DisplayName: p.DisplayName, IssuerURL: p.IssuerURL, ClientID: p.ClientID, Scopes: p.Scopes, Enabled: p.Enabled}
	if patch.DisplayName != nil {
		input.DisplayName = *patch.DisplayName
	}
	if patch.IssuerURL != nil {
		input.IssuerURL = *patch.IssuerURL
	}
	if patch.ClientID != nil {
		input.ClientID = *patch.ClientID
	}
	if patch.Scopes != nil {
		input.Scopes = *patch.Scopes
	}
	if patch.Enabled != nil {
		input.Enabled = *patch.Enabled
	}
	validate := patch.IssuerURL != nil || patch.ClientID != nil || patch.ClientSecret != nil || patch.Scopes != nil || !p.Enabled && input.Enabled
	if patch.ClientSecret != nil {
		input.ClientSecret = *patch.ClientSecret
	} else if validate && len(before.Secret) != 0 {
		plaintext, e := s.ProviderSecrets.Open(providersecret.Binding{TenantID: s.Tenant, ProviderID: id, Purpose: providersecret.OIDCClientSecret}, before.Secret)
		if e != nil {
			return web.OIDCProvider{}, e
		}
		input.ClientSecret = string(plaintext)
		clear(plaintext)
	}
	input, err = web.NormalizeOIDCInput(input)
	if err != nil {
		return web.OIDCProvider{}, err
	}
	if validate {
		if err = s.validateOIDC(ctx, input); err != nil {
			return web.OIDCProvider{}, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.OIDCProvider{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return web.OIDCProvider{}, err
	}
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM identity_providers WHERE id=$1 AND kind='oidc' AND deleted_at IS NULL FOR UPDATE`, id).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return web.OIDCProvider{}, web.ErrOIDCNotFound
	}
	if err != nil {
		return web.OIDCProvider{}, err
	}
	if revision != before.Revision {
		return web.OIDCProvider{}, web.ErrProviderChanged
	}
	if input.IssuerURL != p.IssuerURL {
		var bound bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM user_identities WHERE provider_id=$1)`, id).Scan(&bound); err != nil {
			return web.OIDCProvider{}, err
		}
		if bound {
			return web.OIDCProvider{}, web.ErrProviderInUse
		}
	}
	secret := before.Secret
	if patch.ClientSecret != nil {
		secret, err = s.sealOIDC(id, input.ClientSecret)
		if err != nil {
			return web.OIDCProvider{}, err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE identity_providers SET display_name=$2,enabled=$3,revision=revision+1 WHERE id=$1`, id, input.DisplayName, input.Enabled)
	if err != nil {
		return web.OIDCProvider{}, err
	}
	scopes, _ := json.Marshal(input.Scopes)
	_, err = tx.ExecContext(ctx, `UPDATE oidc_providers SET issuer_url=$2,client_id=$3,scopes=ARRAY(SELECT jsonb_array_elements_text($4::jsonb)),client_secret_enc=$5 WHERE id=$1`, id, input.IssuerURL, input.ClientID, string(scopes), secret)
	if err != nil {
		return web.OIDCProvider{}, err
	}
	if err = providerAudit(ctx, tx, actor, "oidc_provider.updated", id, ip); err != nil {
		return web.OIDCProvider{}, err
	}
	row, err := scanOIDC(tx.QueryRowContext(ctx, `SELECT `+oidcProjection+` FROM identity_providers p JOIN oidc_providers o ON o.tenant_id=p.tenant_id AND o.id=p.id WHERE p.id=$1`, id))
	if err != nil {
		return web.OIDCProvider{}, err
	}
	return row.Provider, tx.Commit()
}

func (s *ConsoleStore) DeleteOIDCProvider(ctx context.Context, actor, id string, ip netip.Addr) error {
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
	err = tx.QueryRowContext(ctx, `SELECT id FROM identity_providers WHERE id=$1 AND kind='oidc' AND deleted_at IS NULL FOR UPDATE`, id).Scan(&provider)
	if errors.Is(err, sql.ErrNoRows) {
		return web.ErrOIDCNotFound
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
	// Retain the provider tombstone and invitation restrictions for audit/history.
	// Never turn a restricted grant into an unrestricted password invitation.
	if _, err = tx.ExecContext(ctx, `UPDATE invites SET cancelled_at=coalesce(cancelled_at,clock_timestamp()) WHERE provider_id=$1 AND used_at IS NULL`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE oidc_providers SET client_secret_enc=NULL WHERE id=$1`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE identity_providers SET enabled=false,deleted_at=clock_timestamp(),revision=revision+1 WHERE id=$1`, id); err != nil {
		return err
	}
	if err = providerAudit(ctx, tx, actor, "oidc_provider.deleted", id, ip); err != nil {
		return err
	}
	return tx.Commit()
}
