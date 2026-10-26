package web

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrOIDCNotFound      = errors.New("OIDC provider unavailable")
	ErrOIDCDiscovery     = errors.New("OIDC discovery failed")
	ErrProviderInUse     = errors.New("provider has bound users")
	ErrProviderChanged   = errors.New("provider configuration changed")
	ErrProviderSlugTaken = errors.New("provider slug already exists")
	ErrProviderInput     = errors.New("invalid provider configuration")
	providerSlug         = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

type OIDCProvider struct {
	ID              string    `json:"id"`
	Slug            string    `json:"slug"`
	DisplayName     string    `json:"display_name"`
	IssuerURL       string    `json:"issuer_url"`
	ClientID        string    `json:"client_id"`
	HasClientSecret bool      `json:"has_client_secret"`
	Scopes          []string  `json:"scopes"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	RedirectURI     string    `json:"redirect_uri"`
}

type OIDCProviderInput struct {
	Slug         string   `json:"slug"`
	DisplayName  string   `json:"display_name"`
	IssuerURL    string   `json:"issuer_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	Enabled      bool     `json:"enabled"`
}

func (OIDCProviderInput) String() string     { return "OIDCProviderInput(redacted)" }
func (v OIDCProviderInput) GoString() string { return v.String() }

type OIDCProviderPatch struct {
	DisplayName  *string
	IssuerURL    *string
	ClientID     *string
	ClientSecret *string
	Scopes       *[]string
	Enabled      *bool
}

func (OIDCProviderPatch) String() string     { return "OIDCProviderPatch(redacted)" }
func (v OIDCProviderPatch) GoString() string { return v.String() }

type OIDCProviderPage struct {
	Items      []OIDCProvider `json:"items"`
	NextCursor *string        `json:"next_cursor"`
}

type OIDCProviderRepository interface {
	OIDCProviders(context.Context, string, UserQuery) (OIDCProviderPage, error)
	CreateOIDCProvider(context.Context, string, OIDCProviderInput, netip.Addr) (OIDCProvider, error)
	UpdateOIDCProvider(context.Context, string, string, OIDCProviderPatch, netip.Addr) (OIDCProvider, error)
	DeleteOIDCProvider(context.Context, string, string, netip.Addr) error
}

// NormalizeOIDCInput is shared by HTTP and repository entry points. Discovery
// and outbound-network checks happen separately after checking live authority.
func NormalizeOIDCInput(v OIDCProviderInput) (OIDCProviderInput, error) {
	text := func(value string, max int) bool {
		if value == "" || len(value) > max || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
			return false
		}
		for _, c := range value {
			if unicode.IsControl(c) {
				return false
			}
		}
		return true
	}
	u, err := url.Parse(v.IssuerURL)
	if !providerSlug.MatchString(v.Slug) || !text(v.DisplayName, 200) || !text(v.ClientID, 4096) || !text(v.IssuerURL, 2048) || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" || strings.Contains(v.IssuerURL, "\\") || len(v.ClientSecret) > 16384 || !utf8.ValidString(v.ClientSecret) || strings.ContainsAny(v.ClientSecret, "\x00\r\n") {
		return OIDCProviderInput{}, ErrProviderInput
	}
	if v.Scopes == nil {
		v.Scopes = []string{"openid", "email", "profile"}
	}
	if len(v.Scopes) == 0 || len(v.Scopes) > 32 {
		return OIDCProviderInput{}, ErrProviderInput
	}
	seen := make(map[string]bool)
	for _, scope := range v.Scopes {
		if len(scope) == 0 || len(scope) > 128 || seen[scope] {
			return OIDCProviderInput{}, ErrProviderInput
		}
		for _, c := range scope {
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return OIDCProviderInput{}, ErrProviderInput
			}
		}
		seen[scope] = true
	}
	if !seen["openid"] {
		return OIDCProviderInput{}, ErrProviderInput
	}
	v.Scopes = append([]string(nil), v.Scopes...)
	return v, nil
}
