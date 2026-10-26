package sso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	authoidc "github.com/KazuhaHub/authcore/oidc"
)

func TestOIDCUsesSharedProtocolAndConsolePolicy(t *testing.T) {
	var endpoint, forbidden, forbiddenField atomic.Value
	forbidden.Store("")
	forbiddenField.Store("authorization_endpoint")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("unexpected fetch: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		issuer := endpoint.Load().(string)
		metadata := map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
			"response_types_supported":              []string{"code"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		}
		if value := forbidden.Load().(string); value != "" {
			metadata[forbiddenField.Load().(string)] = value
		}
		json.NewEncoder(w).Encode(metadata)
	}))
	defer server.Close()
	issuer := server.URL
	endpoint.Store(issuer)
	outbound := tlsOutbound(t, server)
	config := authoidc.Config{IssuerURL: issuer, ClientID: "console", ClientSecret: "private-client-credential", RedirectURL: "https://console.example/api/v1/console/oidc/test/callback"}
	provider, err := NewOIDCProvider(context.Background(), config, outbound)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := provider.Begin()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(begin.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if q.Get("scope") != "openid email profile" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") != begin.State.Value || q.Get("redirect_uri") != config.RedirectURL || strings.Contains(begin.URL, config.ClientSecret) {
		t.Fatal("shared protocol parameters or defaults lost")
	}
	// The authorization endpoint is browser-facing, but still cannot redirect a
	// victim browser to an unapproved internal destination advertised by an IdP.
	forbidden.Store("https://127.0.0.1/authorize")
	for _, field := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		forbiddenField.Store(field)
		if _, err := NewOIDCProvider(context.Background(), config, outbound); !errors.Is(err, authoidc.ErrDiscovery) {
			t.Fatal("private advertised endpoint accepted", field, err)
		}
	}
	forbidden.Store("http://idp.example/authorize")
	if _, err := NewOIDCProvider(context.Background(), config, outbound); err == nil {
		t.Fatal("insecure endpoint accepted")
	}
	if _, err := NewOIDCProvider(context.Background(), config, nil); err == nil {
		t.Fatal("missing network policy accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewOIDCProvider(ctx, config, outbound); err == nil {
		t.Fatal("canceled discovery accepted")
	}
}
