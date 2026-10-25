package web

import (
	"context"
	"net/netip"
)

func (f *fixtureRepository) OIDCProviders(context.Context, string, UserQuery) (OIDCProviderPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.oidcReads++
	return f.oidcPage, f.oidcErr
}
func (f *fixtureRepository) CreateOIDCProvider(_ context.Context, _ string, input OIDCProviderInput, ip netip.Addr) (OIDCProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.oidcWrites++
	f.oidcInput = input
	f.lastIP = ip
	return f.oidcResult, f.oidcErr
}
func (f *fixtureRepository) UpdateOIDCProvider(_ context.Context, _ string, id string, input OIDCProviderPatch, ip netip.Addr) (OIDCProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.oidcWrites++
	f.oidcPatch = input
	f.lastIP = ip
	f.openID = id
	return f.oidcResult, f.oidcErr
}
func (f *fixtureRepository) DeleteOIDCProvider(_ context.Context, _ string, id string, ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.oidcWrites++
	f.lastIP = ip
	f.openID = id
	return f.oidcErr
}
