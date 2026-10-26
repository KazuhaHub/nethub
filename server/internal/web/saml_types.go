package web

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrSAMLNotFound = errors.New("SAML provider unavailable")
	ErrSAMLMetadata = errors.New("SAML metadata validation failed")
)

type SAMLProvider struct {
	ID             string    `json:"id"`
	Slug           string    `json:"slug"`
	DisplayName    string    `json:"display_name"`
	EntityID       string    `json:"entity_id"`
	EmailAttribute string    `json:"email_attribute"`
	Enabled        bool      `json:"enabled"`
	HasSigningKey  bool      `json:"has_signing_key"`
	CreatedAt      time.Time `json:"created_at"`
	MetadataURI    string    `json:"metadata_uri"`
	ACSURI         string    `json:"acs_uri"`
}

type SAMLProviderInput struct {
	Slug           string `json:"slug"`
	DisplayName    string `json:"display_name"`
	EntityID       string `json:"entity_id"`
	MetadataXML    string `json:"metadata_xml"`
	EmailAttribute string `json:"email_attribute"`
	Enabled        bool   `json:"enabled"`
}

func (SAMLProviderInput) String() string     { return "SAMLProviderInput(redacted)" }
func (v SAMLProviderInput) GoString() string { return v.String() }

type SAMLProviderPatch struct {
	DisplayName    *string
	EntityID       *string
	MetadataXML    *string
	EmailAttribute *string
	Enabled        *bool
}

func (SAMLProviderPatch) String() string     { return "SAMLProviderPatch(redacted)" }
func (v SAMLProviderPatch) GoString() string { return v.String() }

type SAMLProviderPage struct {
	Items      []SAMLProvider `json:"items"`
	NextCursor *string        `json:"next_cursor"`
}

type SAMLProviderRepository interface {
	SAMLMetadata(context.Context, string, string, string) ([]byte, error)
	SAMLProviders(context.Context, string, UserQuery) (SAMLProviderPage, error)
	CreateSAMLProvider(context.Context, string, SAMLProviderInput, netip.Addr) (SAMLProvider, error)
	UpdateSAMLProvider(context.Context, string, string, SAMLProviderPatch, netip.Addr) (SAMLProvider, error)
	DeleteSAMLProvider(context.Context, string, string, netip.Addr) error
}

// NormalizeSAMLInput checks sizes and ordinary fields. Trusted metadata parsing
// and endpoint policy run only after the repository verifies live authority.
func NormalizeSAMLInput(input SAMLProviderInput) (SAMLProviderInput, error) {
	text := func(value string, limit int) bool {
		if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
			return false
		}
		for _, c := range value {
			if unicode.IsControl(c) {
				return false
			}
		}
		return true
	}
	if !providerSlug.MatchString(input.Slug) || !text(input.DisplayName, 200) || !text(input.EntityID, 2048) || !text(input.EmailAttribute, 512) || len(input.MetadataXML) == 0 || len(input.MetadataXML) > 1<<20 || !utf8.ValidString(input.MetadataXML) {
		return SAMLProviderInput{}, ErrProviderInput
	}
	return input, nil
}
