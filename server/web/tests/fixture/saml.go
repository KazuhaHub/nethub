package main

import (
	"context"
	"net/netip"

	"github.com/KazuhaHub/nethub/server/internal/web"
)

// This browser fixture has no SAML scenario yet. Keep it empty and fail closed;
// genuine provider behavior is exercised by the PostgreSQL suite.
func (r *repository) SAMLProviders(_ context.Context, actor string, _ web.UserQuery) (web.SAMLProviderPage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.SAMLProviderPage{}, err
	}
	return web.SAMLProviderPage{Items: []web.SAMLProvider{}}, nil
}
func (r *repository) CreateSAMLProvider(_ context.Context, actor string, _ web.SAMLProviderInput, _ netip.Addr) (web.SAMLProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.SAMLProvider{}, err
	}
	return web.SAMLProvider{}, web.ErrSAMLNotFound
}
func (r *repository) UpdateSAMLProvider(_ context.Context, actor, _ string, _ web.SAMLProviderPatch, _ netip.Addr) (web.SAMLProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.SAMLProvider{}, err
	}
	return web.SAMLProvider{}, web.ErrSAMLNotFound
}
func (r *repository) DeleteSAMLProvider(_ context.Context, actor, _ string, _ netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return err
	}
	return web.ErrSAMLNotFound
}
func (r *repository) SAMLMetadata(context.Context, string, string, string) ([]byte, error) {
	return nil, web.ErrSAMLNotFound
}
