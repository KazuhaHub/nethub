package web

import (
	"context"
	"net/netip"
)

func (f *fixtureRepository) SAMLMetadata(context.Context, string, string, string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.samlReads++
	return []byte(`<EntityDescriptor/>`), f.samlErr
}

func (f *fixtureRepository) SAMLProviders(context.Context, string, UserQuery) (SAMLProviderPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.samlReads++
	return f.samlPage, f.samlErr
}
func (f *fixtureRepository) CreateSAMLProvider(_ context.Context, _ string, input SAMLProviderInput, ip netip.Addr) (SAMLProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.samlWrites++
	f.samlInput = input
	f.lastIP = ip
	return f.samlResult, f.samlErr
}
func (f *fixtureRepository) UpdateSAMLProvider(_ context.Context, _ string, id string, input SAMLProviderPatch, ip netip.Addr) (SAMLProvider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.samlWrites++
	f.samlPatch = input
	f.lastIP = ip
	f.openID = id
	return f.samlResult, f.samlErr
}
func (f *fixtureRepository) DeleteSAMLProvider(_ context.Context, _ string, id string, ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.samlWrites++
	f.lastIP = ip
	f.openID = id
	return f.samlErr
}
