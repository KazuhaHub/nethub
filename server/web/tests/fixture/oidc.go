package main

import (
	"context"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"net/netip"
)

// Provider administration requires genuine SQL/discovery acceptance. The UI
// fixture does not impersonate those boundaries before provider pages exist.
func (*repository) OIDCProviders(context.Context, string, web.UserQuery) (web.OIDCProviderPage, error) {
	return web.OIDCProviderPage{Items: []web.OIDCProvider{}}, nil
}
func (*repository) CreateOIDCProvider(context.Context, string, web.OIDCProviderInput, netip.Addr) (web.OIDCProvider, error) {
	return web.OIDCProvider{}, web.ErrOIDCDiscovery
}
func (*repository) UpdateOIDCProvider(context.Context, string, string, web.OIDCProviderPatch, netip.Addr) (web.OIDCProvider, error) {
	return web.OIDCProvider{}, web.ErrOIDCNotFound
}
func (*repository) DeleteOIDCProvider(context.Context, string, string, netip.Addr) error {
	return web.ErrOIDCNotFound
}
