package sso

import (
	"context"
	"time"

	authoidc "github.com/KazuhaHub/authcore/oidc"
)

// NewOIDCProvider delegates protocol verification to authcore and supplies the
// console's outbound policy. Account admission and one-use browser state remain
// the repository's responsibility, not the protocol module's.
func NewOIDCProvider(ctx context.Context, config authoidc.Config, outbound *Outbound) (*authoidc.Provider, error) {
	if ctx == nil || outbound == nil {
		return nil, authoidc.ErrInvalidConfig
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := outbound.ValidateEndpoint(ctx, config.IssuerURL); err != nil {
		return nil, authoidc.ErrDiscovery
	}
	config.HTTPClient = outbound.Client()
	config.Timeout = 10 * time.Second
	config.MaxResponseBytes = maxSSOResponse
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"openid", "email", "profile"}
	}
	provider, err := authoidc.New(ctx, config)
	if err != nil {
		return nil, err
	}
	metadata, err := provider.Metadata()
	if err != nil {
		return nil, authoidc.ErrDiscovery
	}
	for _, value := range []string{metadata.AuthorizationEndpoint, metadata.TokenEndpoint, metadata.JWKSURI} {
		if err := outbound.ValidateEndpoint(ctx, value); err != nil {
			return nil, authoidc.ErrDiscovery
		}
	}
	return provider, nil
}
