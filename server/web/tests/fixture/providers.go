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

func (r *repository) resetProvidersLocked() {
	r.users = fixtureUsers()
	r.sessions = map[string]auth.SessionRecord{}
	r.providers = map[string]web.OIDCProvider{}
	r.providerSequence = 3100
	r.invites = map[string]fixtureInvitation{}
	for i := range 52 {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", 3000+i)
		p := web.OIDCProvider{ID: id, Slug: fmt.Sprintf("provider-%02d", i), DisplayName: fmt.Sprintf("Provider %02d", i), IssuerURL: "https://identity.example.com", ClientID: "nethub-console", Scopes: []string{"openid", "email", "profile"}, Enabled: i < 2, HasClientSecret: true, CreatedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
		if i == 0 {
			p.Slug = "corporate"
			p.DisplayName = "Corporate SSO"
		}
		r.providers[id] = p
	}
}
func (r *repository) OIDCProviders(_ context.Context, actor string, query web.UserQuery) (web.OIDCProviderPage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.OIDCProviderPage{}, err
	}
	ids := []string{}
	for id := range r.providers {
		if id > query.AfterID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	page := web.OIDCProviderPage{Items: []web.OIDCProvider{}}
	for _, id := range ids {
		page.Items = append(page.Items, r.providers[id])
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		value := base64.RawURLEncoding.EncodeToString([]byte(page.Items[len(page.Items)-1].ID))
		page.NextCursor = &value
	}
	return page, nil
}
func (r *repository) CreateOIDCProvider(_ context.Context, actor string, input web.OIDCProviderInput, _ netip.Addr) (web.OIDCProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.OIDCProvider{}, err
	}
	input, err := web.NormalizeOIDCInput(input)
	if err != nil {
		return web.OIDCProvider{}, err
	}
	if input.IssuerURL == "https://unavailable.example" {
		return web.OIDCProvider{}, web.ErrOIDCDiscovery
	}
	for _, p := range r.providers {
		if p.Slug == input.Slug {
			return web.OIDCProvider{}, web.ErrProviderSlugTaken
		}
	}
	if r.providers == nil {
		r.providers = map[string]web.OIDCProvider{}
	}
	r.providerSequence++
	p := web.OIDCProvider{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", r.providerSequence), Slug: input.Slug, DisplayName: input.DisplayName, IssuerURL: input.IssuerURL, ClientID: input.ClientID, Scopes: input.Scopes, HasClientSecret: input.ClientSecret != "", Enabled: input.Enabled, CreatedAt: time.Now().UTC()}
	r.providers[p.ID] = p
	return p, nil
}
func (r *repository) UpdateOIDCProvider(_ context.Context, actor, id string, patch web.OIDCProviderPatch, _ netip.Addr) (web.OIDCProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.OIDCProvider{}, err
	}
	p, ok := r.providers[id]
	if !ok {
		return web.OIDCProvider{}, web.ErrOIDCNotFound
	}
	if patch.DisplayName != nil {
		p.DisplayName = *patch.DisplayName
	}
	if patch.IssuerURL != nil {
		if p.Slug == "corporate" && *patch.IssuerURL != p.IssuerURL {
			return web.OIDCProvider{}, web.ErrProviderInUse
		}
		p.IssuerURL = *patch.IssuerURL
	}
	if patch.ClientID != nil {
		p.ClientID = *patch.ClientID
	}
	if patch.Scopes != nil {
		p.Scopes = *patch.Scopes
	}
	if patch.Enabled != nil {
		p.Enabled = *patch.Enabled
	}
	if patch.ClientSecret != nil {
		p.HasClientSecret = *patch.ClientSecret != ""
	}
	r.providers[id] = p
	return p, nil
}
func (r *repository) DeleteOIDCProvider(_ context.Context, actor, id string, _ netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return err
	}
	p, ok := r.providers[id]
	if !ok {
		return web.ErrOIDCNotFound
	}
	if p.Slug == "corporate" {
		return web.ErrProviderInUse
	}
	delete(r.providers, id)
	return nil
}

// This fixture proves UI navigation only. It performs no code exchange and
// cannot establish an SSO account/session; signed IdP and SQL tests are separate.
type fixtureSSO struct {
	repository *repository
	origin     string
}

func (f *fixtureSSO) Providers(context.Context) ([]sso.Choice, error) {
	f.repository.mu.Lock()
	defer f.repository.mu.Unlock()
	choices := []sso.Choice{}
	for _, p := range f.repository.providers {
		if p.Enabled {
			choices = append(choices, sso.Choice{Slug: p.Slug, DisplayName: p.DisplayName})
		}
	}
	sort.Slice(choices, func(i, j int) bool { return choices[i].Slug < choices[j].Slug })
	return choices, nil
}
func (f *fixtureSSO) Start(_ context.Context, slug, invite string) (sso.StartResult, error) {
	f.repository.mu.Lock()
	defer f.repository.mu.Unlock()
	found := slug == "restricted"
	for _, p := range f.repository.providers {
		if p.Slug == slug && p.Enabled {
			found = true
		}
	}
	if !found {
		return sso.StartResult{}, sso.ErrFlow
	}
	if invite != "" {
		digest, err := auth.InvitationDigest(invite)
		if err != nil {
			return sso.StartResult{}, sso.ErrFlow
		}
		if _, ok := f.repository.invites[string(digest)]; !ok {
			return sso.StartResult{}, sso.ErrFlow
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return sso.StartResult{}, err
	}
	return sso.StartResult{RedirectURL: f.origin + "/test/oidc-authorize", BrowserToken: base64.RawURLEncoding.EncodeToString(raw), ExpiresAt: time.Now().Add(sso.FlowLifetime)}, nil
}
func (*fixtureSSO) Complete(context.Context, string, string, string, string, string, netip.Addr, string) (auth.LoginResult, bool, error) {
	return auth.LoginResult{}, false, sso.ErrFlow
}
func (*fixtureSSO) Failed(context.Context, netip.Addr, string) error { return nil }
