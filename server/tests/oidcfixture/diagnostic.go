package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	authoidc "github.com/KazuhaHub/authcore/oidc"
	"github.com/KazuhaHub/nethub/server/internal/sso"
)

func diagnosticError(err error) string {
	var dns *net.DNSError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var network net.Error
	switch {
	case err == nil:
		return "none"
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &unknown):
		return "certificate_authority"
	case errors.As(err, &hostname):
		return "certificate_hostname"
	case errors.As(err, &invalid):
		return "certificate_validity"
	case errors.As(err, &network) && network.Timeout():
		return "deadline"
	case errors.Is(err, sso.ErrOutbound):
		return "console_outbound"
	case errors.Is(err, authoidc.ErrDiscovery):
		return "console_discovery"
	case errors.Is(err, authoidc.ErrUnsupportedAuthMethod):
		return "console_auth_method"
	case errors.Is(err, authoidc.ErrInvalidConfig):
		return "console_configuration"
	default:
		return "transport_or_protocol"
	}
}

// checkProvider runs beside Web in its network namespace. It performs discovery
// only, without authenticating or creating state, and emits no URLs or errors.
func checkProvider(directory, slug string, output io.Writer) error {
	if !filepath.IsAbs(directory) || slug != "one" && slug != "two" {
		return errors.New("invalid provider diagnostic target")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "credentials.json"))
	if err != nil {
		return err
	}
	var secrets credentials
	if err := json.Unmarshal(raw, &secrets); err != nil {
		return err
	}
	root, err := os.ReadFile(filepath.Join(directory, "root.crt"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		return errors.New("invalid diagnostic trust")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	host := "dex-" + slug + ".test"
	issuer := "https://" + host
	addresses, dnsErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	result := map[string]any{"dns_resolved": dnsErr == nil && len(addresses) > 0}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("diagnostic redirect refused") }}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	response, networkErr := client.Do(request)
	result["network_error"] = diagnosticError(networkErr)
	if networkErr == nil {
		defer response.Body.Close()
		result["discovery_status"] = response.StatusCode
		var metadata struct {
			Issuer    string   `json:"issuer"`
			Responses []string `json:"response_types_supported"`
			Signing   []string `json:"id_token_signing_alg_values_supported"`
			Methods   []string `json:"token_endpoint_auth_methods_supported"`
		}
		if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&metadata) == nil {
			result["metadata_issuer_matches"] = metadata.Issuer == issuer
			result["metadata_code_supported"] = slices.Contains(metadata.Responses, "code")
			result["metadata_signing_rs256"] = slices.Contains(metadata.Signing, "RS256")
			result["metadata_basic_auth"] = slices.Contains(metadata.Methods, "client_secret_basic")
		}
	}
	outbound, err := sso.NewOutbound([]string{"dex-one.test", "dex-two.test"})
	if err != nil {
		return err
	}
	defer outbound.CloseIdleConnections()
	provider, protocolErr := sso.NewOIDCProvider(ctx, authoidc.Config{IssuerURL: issuer, ClientID: "nethub-" + slug, ClientSecret: secrets.Clients[slug], RedirectURL: consoleOrigin + "/api/v1/console/oidc/" + slug + "/callback"}, outbound)
	if provider != nil {
		provider.CloseIdleConnections()
	}
	result["console_discovery_ok"] = protocolErr == nil
	result["console_error"] = diagnosticError(protocolErr)
	return json.NewEncoder(output).Encode(result)
}
