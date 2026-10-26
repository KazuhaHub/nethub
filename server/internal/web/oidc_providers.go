package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

func (s *Server) providerError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrProviderInput):
		writeError(w, r, 400, "invalid_request", "Invalid provider configuration")
	case errors.Is(err, ErrOIDCNotFound), errors.Is(err, ErrSAMLNotFound):
		writeError(w, r, 404, "not_found", "Provider unavailable")
	case errors.Is(err, ErrOIDCDiscovery):
		writeError(w, r, 422, "oidc_discovery_failed", "Provider discovery failed")
	case errors.Is(err, ErrSAMLMetadata):
		writeError(w, r, 422, "saml_metadata_invalid", "Provider metadata validation failed")
	case errors.Is(err, ErrProviderSlugTaken):
		writeError(w, r, 409, "slug_taken", "Provider slug already exists")
	case errors.Is(err, ErrProviderInUse):
		writeError(w, r, 409, "provider_in_use", "Provider has bound users; disable it instead")
	case errors.Is(err, ErrProviderChanged):
		writeError(w, r, 409, "provider_changed", "Provider changed; reload before editing")
	case errors.Is(err, auth.ErrUnauthenticated):
		writeError(w, r, 401, "unauthenticated", "Sign in to continue")
	case errors.Is(err, ErrForbidden):
		writeError(w, r, 403, "forbidden", "Administrator access required")
	default:
		s.internal(w, r, "Identity provider")
	}
}

func (s *Server) providerRedirect(p OIDCProvider) OIDCProvider {
	p.RedirectURI = "https://" + s.host + prefix + "/oidc/" + p.Slug + "/callback"
	return p
}

func (s *Server) oidcProviders(w http.ResponseWriter, r *http.Request) {
	session, ok := s.adminSession(w, r, false)
	if !ok {
		return
	}
	values, err := netURLQuery(r)
	if err != nil {
		s.providerError(w, r, ErrProviderInput)
		return
	}
	query := UserQuery{Limit: 50}
	for key, list := range values {
		if len(list) != 1 {
			s.providerError(w, r, ErrProviderInput)
			return
		}
		switch key {
		case "limit":
			query.Limit, err = strconv.Atoi(list[0])
			if err != nil || query.Limit < 1 || query.Limit > 200 {
				s.providerError(w, r, ErrProviderInput)
				return
			}
		case "cursor":
			value, e := base64.RawURLEncoding.Strict().DecodeString(list[0])
			if e != nil || len(list[0]) > 64 || !uuidPattern.Match(value) {
				s.providerError(w, r, ErrProviderInput)
				return
			}
			query.AfterID = string(value)
		default:
			s.providerError(w, r, ErrProviderInput)
			return
		}
	}
	page, err := s.repository.OIDCProviders(r.Context(), session.User.ID, query)
	if err != nil {
		s.providerError(w, r, err)
		return
	}
	for i, p := range page.Items {
		page.Items[i] = s.providerRedirect(p)
	}
	writeJSON(w, r, 200, page)
}

func readOIDCPatch(w http.ResponseWriter, r *http.Request, create bool) (string, OIDCProviderPatch, bool) {
	fields := []string{"display_name", "issuer_url", "client_id", "client_secret", "scopes", "enabled"}
	if create {
		fields = append(fields, "slug")
	}
	var raw map[string]json.RawMessage
	if !readJSON(w, r, &raw, fields...) {
		return "", OIDCProviderPatch{}, false
	}
	var patch OIDCProviderPatch
	var slug string
	for key, value := range raw {
		var target any
		switch key {
		case "slug":
			target = &slug
		case "display_name":
			patch.DisplayName = new(string)
			target = patch.DisplayName
		case "issuer_url":
			patch.IssuerURL = new(string)
			target = patch.IssuerURL
		case "client_id":
			patch.ClientID = new(string)
			target = patch.ClientID
		case "client_secret":
			patch.ClientSecret = new(string)
			target = patch.ClientSecret
		case "scopes":
			patch.Scopes = new([]string)
			target = patch.Scopes
		case "enabled":
			patch.Enabled = new(bool)
			target = patch.Enabled
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, target) != nil {
			writeError(w, r, 400, "invalid_request", "Provider fields cannot be null and must use their documented types")
			return "", OIDCProviderPatch{}, false
		}
	}
	if len(raw) == 0 || create && (slug == "" || patch.DisplayName == nil || patch.IssuerURL == nil || patch.ClientID == nil) {
		writeError(w, r, 400, "invalid_request", "Provide the required provider fields")
		return "", OIDCProviderPatch{}, false
	}
	return slug, patch, true
}

func (s *Server) createOIDCProvider(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, ok := s.adminSession(w, r, true)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		s.providerError(w, r, ErrProviderInput)
		return
	}
	slug, patch, ok := readOIDCPatch(w, r, true)
	if !ok {
		return
	}
	input := OIDCProviderInput{Slug: slug, DisplayName: *patch.DisplayName, IssuerURL: *patch.IssuerURL, ClientID: *patch.ClientID}
	if patch.ClientSecret != nil {
		input.ClientSecret = *patch.ClientSecret
	}
	if patch.Scopes != nil {
		input.Scopes = *patch.Scopes
	}
	if patch.Enabled != nil {
		input.Enabled = *patch.Enabled
	}
	input, err := NormalizeOIDCInput(input)
	if err != nil {
		s.providerError(w, r, err)
		return
	}
	p, err := s.repository.CreateOIDCProvider(r.Context(), session.User.ID, input, ip.Unmap())
	if err != nil {
		s.providerError(w, r, err)
		return
	}
	writeJSON(w, r, 201, s.providerRedirect(p))
}

func (s *Server) mutateOIDCProvider(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, ok := s.adminSession(w, r, true)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, prefix+"/oidc-providers/")
	if !uuidPattern.MatchString(id) || r.URL.RawQuery != "" {
		s.providerError(w, r, ErrProviderInput)
		return
	}
	if r.Method == "DELETE" {
		if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			s.providerError(w, r, ErrProviderInput)
			return
		}
		if err := s.repository.DeleteOIDCProvider(r.Context(), session.User.ID, id, ip.Unmap()); err != nil {
			s.providerError(w, r, err)
			return
		}
		w.WriteHeader(204)
		return
	}
	_, patch, ok := readOIDCPatch(w, r, false)
	if !ok {
		return
	}
	p, err := s.repository.UpdateOIDCProvider(r.Context(), session.User.ID, id, patch, ip.Unmap())
	if err != nil {
		s.providerError(w, r, err)
		return
	}
	writeJSON(w, r, 200, s.providerRedirect(p))
}
