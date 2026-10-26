package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	authsaml "github.com/KazuhaHub/authcore/saml"
	"github.com/KazuhaHub/nethub/server/internal/auth"
	crewjamsaml "github.com/crewjam/saml"
)

type SAMLLoginProvider struct {
	ID, Slug, DisplayName, EmailAttribute string
	Revision                              int64
	Config                                authsaml.Config
}

func (SAMLLoginProvider) String() string     { return "SAMLLoginProvider(redacted)" }
func (p SAMLLoginProvider) GoString() string { return p.String() }

type SAMLFlowInput struct {
	Provider                        SAMLLoginProvider
	State, RequestID                string
	BrowserDigest, InvitationDigest []byte
}

func (SAMLFlowInput) String() string     { return "SAMLFlowInput(redacted)" }
func (v SAMLFlowInput) GoString() string { return v.String() }

type ConsumedSAMLFlow struct {
	ID, RequestID string
	Provider      SAMLLoginProvider
}

func (ConsumedSAMLFlow) String() string     { return "ConsumedSAMLFlow(redacted)" }
func (v ConsumedSAMLFlow) GoString() string { return v.String() }

type SAMLFlowRepository interface {
	SAMLLoginProviders(context.Context) ([]Choice, error)
	SAMLLoginProvider(context.Context, string) (SAMLLoginProvider, error)
	SaveSAMLFlow(context.Context, SAMLFlowInput) (time.Time, error)
	ConsumeSAMLFlow(context.Context, string, string, []byte) (ConsumedSAMLFlow, error)
	SSOFailed(context.Context, netip.Addr, string) error
}

type SAMLService struct {
	repository SAMLFlowRepository
	sessions   *auth.Service
	outbound   *Outbound
	origin     string
}

func NewSAMLService(origin string, repository SAMLFlowRepository, sessions *auth.Service, outbound *Outbound) (*SAMLService, error) {
	if _, err := auth.NewOriginPolicy(origin); err != nil || repository == nil || sessions == nil || outbound == nil {
		return nil, ErrFlow
	}
	u, _ := url.Parse(origin)
	return &SAMLService{repository: repository, sessions: sessions, outbound: outbound, origin: "https://" + strings.TrimSuffix(strings.ToLower(u.Host), ":443")}, nil
}

func ValidSAMLRequestID(value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func opaqueSAMLToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(raw[:])
	clear(raw[:])
	return value, nil
}

func (s *SAMLService) Providers(ctx context.Context) ([]Choice, error) {
	return s.repository.SAMLLoginProviders(ctx)
}
func (s *SAMLService) Failed(ctx context.Context, ip netip.Addr, reason string) error {
	return s.repository.SSOFailed(ctx, ip, reason)
}

func (s *SAMLService) protocol(ctx context.Context, p SAMLLoginProvider, starting bool) (*authsaml.Provider, error) {
	metadata := p.Config.IDPMetadata
	if metadata == nil || !metadata.ValidUntil.IsZero() && !time.Now().Before(metadata.ValidUntil) {
		return nil, ErrFlow
	}
	if starting {
		for _, role := range metadata.IDPSSODescriptors {
			for _, endpoint := range role.SingleSignOnServices {
				if endpoint.Binding == crewjamsaml.HTTPRedirectBinding {
					if err := s.outbound.ValidateEndpoint(ctx, endpoint.Location); err != nil {
						return nil, ErrFlow
					}
				}
			}
		}
	}
	p.Config.EntityID = s.origin + "/api/v1/console/saml/" + p.Slug + "/metadata"
	p.Config.ACSURL = s.origin + "/api/v1/console/saml/" + p.Slug + "/callback"
	p.Config.SignAuthnRequests = true
	p.Config.AllowEncryptedAssertions = true
	p.Config.MaxResponseBytes = 1 << 20
	return NewSAMLProvider(p.Config)
}

func (s *SAMLService) Start(ctx context.Context, slug, invite string) (StartResult, error) {
	var invitation []byte
	var err error
	if invite != "" {
		invitation, err = auth.InvitationDigest(invite)
		if err != nil {
			return StartResult{}, failedFlow("invitation_invalid")
		}
	}
	p, err := s.repository.SAMLLoginProvider(ctx, slug)
	if err != nil {
		return StartResult{}, failedFlow("provider_unavailable")
	}
	protocol, err := s.protocol(ctx, p, true)
	if err != nil {
		return StartResult{}, failedFlow("discovery_failed")
	}
	state, err := opaqueSAMLToken()
	if err != nil {
		return StartResult{}, failedFlow("state_unavailable")
	}
	request, err := protocol.NewAuthnRequest(state)
	if err != nil || request == nil || !ValidSAMLRequestID(request.ID) {
		return StartResult{}, failedFlow("state_unavailable")
	}
	browser, err := opaqueSAMLToken()
	if err != nil {
		return StartResult{}, failedFlow("state_unavailable")
	}
	digest, _ := Digest(browser)
	expires, err := s.repository.SaveSAMLFlow(ctx, SAMLFlowInput{Provider: p, State: state, RequestID: request.ID, BrowserDigest: digest, InvitationDigest: invitation})
	if err != nil {
		return StartResult{}, failedFlow("state_unavailable")
	}
	return StartResult{RedirectURL: request.RedirectURL, BrowserToken: browser, ExpiresAt: expires}, nil
}

// Complete consumes the browser-bound receipt before authcore sees an assertion.
// A failed verification never restores that receipt or retries admission.
func (s *SAMLService) Complete(ctx context.Context, slug, state, response, browser string, ip netip.Addr, userAgent string) (auth.LoginResult, bool, error) {
	if !ip.IsValid() || ip.Zone() != "" || len(userAgent) > 1024 {
		return auth.LoginResult{}, false, failedFlow("callback")
	}
	digest, err := Digest(browser)
	if err != nil {
		return auth.LoginResult{}, false, failedFlow("state_invalid")
	}
	flow, err := s.repository.ConsumeSAMLFlow(ctx, slug, state, digest)
	if err != nil {
		return auth.LoginResult{}, false, failedFlow("state_invalid")
	}
	if response == "" || len(response) > 2<<20 {
		return auth.LoginResult{}, true, failedFlow("callback")
	}
	protocol, err := s.protocol(ctx, flow.Provider, false)
	if err != nil {
		return auth.LoginResult{}, true, failedFlow("discovery_failed")
	}
	acs := s.origin + "/api/v1/console/saml/" + flow.Provider.Slug + "/callback"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, acs, strings.NewReader(url.Values{"SAMLResponse": {response}}.Encode()))
	if err != nil {
		return auth.LoginResult{}, true, failedFlow("callback")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assertion, err := protocol.ValidateResponse(ctx, request, []string{flow.RequestID})
	if err != nil {
		return auth.LoginResult{}, true, failedFlow("token_invalid")
	}
	identity, err := (SAMLIdentityPolicy{Issuer: flow.Provider.Config.IDPMetadata.EntityID, EntityID: s.origin + "/api/v1/console/saml/" + flow.Provider.Slug + "/metadata", EmailAttribute: flow.Provider.EmailAttribute}).Identity(assertion)
	if err != nil {
		return auth.LoginResult{}, true, failedFlow("token_invalid")
	}
	result, err := s.sessions.LoginExternal(ctx, auth.ExternalIdentity{Protocol: "saml", FlowID: flow.ID, ProviderID: flow.Provider.ID, ProviderRevision: flow.Provider.Revision, Issuer: identity.Issuer, Subject: identity.Subject, Email: identity.Email, SignedEmail: identity.Email != ""}, ip, userAgent)
	if err != nil {
		return auth.LoginResult{}, true, failedFlow("admission_denied")
	}
	return result, true, nil
}
