package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/sso"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

// These synthetic rows exercise UI behavior only. They do not issue assertions,
// generate SP keys, or establish SAML accounts; genuine protocol/SQL tests remain separate.
func (r *repository) resetSAMLProvidersLocked() {
	r.resetProvidersLocked()
	r.samlProviders = map[string]web.SAMLProvider{}
	r.samlReserved = map[string]bool{}
	r.samlSequence = 5100
	for i := range 52 {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", 5000+i)
		slug := fmt.Sprintf("saml-%02d", i)
		name := fmt.Sprintf("SAML Provider %02d", i)
		if i == 0 {
			slug = "company-saml"
			name = "Company SAML"
		}
		r.samlProviders[id] = web.SAMLProvider{ID: id, Slug: slug, DisplayName: name, EntityID: "urn:company:identity", EmailAttribute: "mail", Enabled: i < 2, HasSigningKey: true, CreatedAt: time.Now().UTC()}
		r.samlReserved[slug] = true
	}
}
func (r *repository) SAMLProviders(_ context.Context, actor string, query web.UserQuery) (web.SAMLProviderPage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.SAMLProviderPage{}, err
	}
	ids := []string{}
	for id := range r.samlProviders {
		if id > query.AfterID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	page := web.SAMLProviderPage{Items: []web.SAMLProvider{}}
	for _, id := range ids {
		page.Items = append(page.Items, r.samlProviders[id])
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		cursor := base64.RawURLEncoding.EncodeToString([]byte(page.Items[len(page.Items)-1].ID))
		page.NextCursor = &cursor
	}
	return page, nil
}
func (r *repository) CreateSAMLProvider(_ context.Context, actor string, input web.SAMLProviderInput, _ netip.Addr) (web.SAMLProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.SAMLProvider{}, err
	}
	input, err := web.NormalizeSAMLInput(input)
	if err != nil {
		return web.SAMLProvider{}, err
	}
	if input.MetadataXML == "invalid-metadata" {
		return web.SAMLProvider{}, web.ErrSAMLMetadata
	}
	if r.samlReserved[input.Slug] {
		return web.SAMLProvider{}, web.ErrProviderSlugTaken
	}
	for _, p := range r.providers {
		if p.Slug == input.Slug {
			return web.SAMLProvider{}, web.ErrProviderSlugTaken
		}
	}
	if r.samlProviders == nil {
		r.samlProviders = map[string]web.SAMLProvider{}
		r.samlReserved = map[string]bool{}
	}
	r.samlSequence++
	p := web.SAMLProvider{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", r.samlSequence), Slug: input.Slug, DisplayName: input.DisplayName, EntityID: input.EntityID, EmailAttribute: input.EmailAttribute, Enabled: input.Enabled, HasSigningKey: true, CreatedAt: time.Now().UTC()}
	r.samlProviders[p.ID] = p
	r.samlReserved[p.Slug] = true
	return p, nil
}
func (r *repository) UpdateSAMLProvider(_ context.Context, actor, id string, patch web.SAMLProviderPatch, _ netip.Addr) (web.SAMLProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.SAMLProvider{}, err
	}
	p, ok := r.samlProviders[id]
	if !ok {
		return web.SAMLProvider{}, web.ErrSAMLNotFound
	}
	if patch.EntityID != nil && p.Slug == "company-saml" && *patch.EntityID != p.EntityID {
		return web.SAMLProvider{}, web.ErrProviderInUse
	}
	if patch.MetadataXML != nil && *patch.MetadataXML == "invalid-metadata" {
		return web.SAMLProvider{}, web.ErrSAMLMetadata
	}
	if patch.DisplayName != nil {
		p.DisplayName = *patch.DisplayName
	}
	if patch.EntityID != nil {
		p.EntityID = *patch.EntityID
	}
	if patch.EmailAttribute != nil {
		p.EmailAttribute = *patch.EmailAttribute
	}
	if patch.Enabled != nil {
		p.Enabled = *patch.Enabled
	}
	r.samlProviders[id] = p
	return p, nil
}
func (r *repository) DeleteSAMLProvider(_ context.Context, actor, id string, _ netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return err
	}
	p, ok := r.samlProviders[id]
	if !ok {
		return web.ErrSAMLNotFound
	}
	if p.Slug == "company-saml" {
		return web.ErrProviderInUse
	}
	delete(r.samlProviders, id)
	return nil
}
func (r *repository) SAMLMetadata(_ context.Context, slug, _ string, _ string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.samlProviders {
		if p.Slug == slug {
			return []byte(`<EntityDescriptor/>`), nil
		}
	}
	return nil, web.ErrSAMLNotFound
}

type fixtureSAML struct {
	repository *repository
	origin     string
}

func (f *fixtureSAML) Providers(context.Context) ([]sso.Choice, error) {
	f.repository.mu.Lock()
	defer f.repository.mu.Unlock()
	choices := []sso.Choice{}
	for _, p := range f.repository.samlProviders {
		if p.Enabled {
			choices = append(choices, sso.Choice{Protocol: "saml", Slug: p.Slug, DisplayName: p.DisplayName})
		}
	}
	sort.Slice(choices, func(i, j int) bool { return choices[i].Slug < choices[j].Slug })
	return choices, nil
}
func (f *fixtureSAML) Start(_ context.Context, slug, invite string) (sso.StartResult, error) {
	f.repository.mu.Lock()
	defer f.repository.mu.Unlock()
	var id string
	for _, p := range f.repository.samlProviders {
		if p.Slug == slug && p.Enabled {
			id = p.ID
		}
	}
	if id == "" {
		return sso.StartResult{}, sso.ErrFlow
	}
	if invite != "" {
		digest, err := auth.InvitationDigest(invite)
		if err != nil {
			return sso.StartResult{}, sso.ErrFlow
		}
		grant, ok := f.repository.invites[string(digest)]
		if !ok || grant.ProviderID != nil && *grant.ProviderID != id {
			return sso.StartResult{}, sso.ErrFlow
		}
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return sso.StartResult{}, err
	}
	return sso.StartResult{RedirectURL: f.origin + "/test/saml-authorize", BrowserToken: base64.RawURLEncoding.EncodeToString(raw[:]), ExpiresAt: time.Now().Add(sso.FlowLifetime)}, nil
}
func (*fixtureSAML) Complete(context.Context, string, string, string, string, netip.Addr, string) (auth.LoginResult, bool, error) {
	return auth.LoginResult{}, false, sso.ErrFlow
}
func (*fixtureSAML) Failed(context.Context, netip.Addr, string) error { return nil }
