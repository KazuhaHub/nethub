package sso

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"time"

	authoidc "github.com/KazuhaHub/authcore/oidc"
	"github.com/KazuhaHub/nethub/server/internal/auth"
)

var ErrFlow = errors.New("SSO sign-in failed")

const FlowLifetime = 5 * time.Minute

type Choice struct {
	Protocol    string `json:"protocol,omitempty"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

type LoginProvider struct {
	ID, Slug, DisplayName string
	Revision              int64
	Config                authoidc.Config
}

func (LoginProvider) String() string     { return "LoginProvider(redacted)" }
func (p LoginProvider) GoString() string { return p.String() }

type FlowInput struct {
	Provider                        LoginProvider
	State                           authoidc.State
	BrowserDigest, InvitationDigest []byte
}

func (FlowInput) String() string     { return "FlowInput(redacted)" }
func (v FlowInput) GoString() string { return v.String() }

type ConsumedFlow struct {
	ID       string
	Provider LoginProvider
	State    authoidc.State
}

func (ConsumedFlow) String() string     { return "ConsumedFlow(redacted)" }
func (v ConsumedFlow) GoString() string { return v.String() }

type FlowRepository interface {
	LoginProviders(context.Context) ([]Choice, error)
	LoginProvider(context.Context, string) (LoginProvider, error)
	SaveOIDCFlow(context.Context, FlowInput) (time.Time, error)
	ConsumeOIDCFlow(context.Context, string, string, []byte) (ConsumedFlow, error)
	SSOFailed(context.Context, netip.Addr, string) error
}

type StartResult struct {
	RedirectURL  string    `json:"-"`
	BrowserToken string    `json:"-"`
	ExpiresAt    time.Time `json:"-"`
}

func (StartResult) String() string     { return "StartResult(redacted)" }
func (v StartResult) GoString() string { return v.String() }

type Service struct {
	repository FlowRepository
	sessions   *auth.Service
	outbound   *Outbound
	origin     string
}

func NewService(origin string, repository FlowRepository, sessions *auth.Service, outbound *Outbound) (*Service, error) {
	if _, err := auth.NewOriginPolicy(origin); err != nil || repository == nil || sessions == nil || outbound == nil {
		return nil, ErrFlow
	}
	u, _ := url.Parse(origin)
	return &Service{repository: repository, sessions: sessions, outbound: outbound, origin: "https://" + strings.TrimSuffix(strings.ToLower(u.Host), ":443")}, nil
}

func Digest(value string) ([]byte, error) {
	digest, err := auth.InvitationDigest(value)
	if err != nil {
		return nil, ErrFlow
	}
	return digest, nil
}

func ValidState(state authoidc.State) bool {
	for _, value := range []string{state.Value, state.Nonce, state.Verifier, state.Configuration} {
		if _, err := Digest(value); err != nil {
			return false
		}
	}
	return true
}

func (s *Service) Providers(ctx context.Context) ([]Choice, error) {
	return s.repository.LoginProviders(ctx)
}

func (s *Service) protocol(ctx context.Context, p LoginProvider) (*authoidc.Provider, error) {
	p.Config.RedirectURL = s.origin + "/api/v1/console/oidc/" + p.Slug + "/callback"
	return NewOIDCProvider(ctx, p.Config, s.outbound)
}

func (s *Service) Start(ctx context.Context, slug, invite string) (StartResult, error) {
	var invitation []byte
	var err error
	if invite != "" {
		invitation, err = auth.InvitationDigest(invite)
		if err != nil {
			return StartResult{}, failedFlow("invitation_invalid")
		}
	}
	p, err := s.repository.LoginProvider(ctx, slug)
	if err != nil {
		return StartResult{}, failedFlow("provider_unavailable")
	}
	protocol, err := s.protocol(ctx, p)
	if err != nil {
		return StartResult{}, failedFlow("discovery_failed")
	}
	authorization, err := protocol.Begin()
	if err != nil {
		return StartResult{}, failedFlow("state_unavailable")
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return StartResult{}, failedFlow("state_unavailable")
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	digest, _ := Digest(token)
	expires, err := s.repository.SaveOIDCFlow(ctx, FlowInput{Provider: p, State: authorization.State, BrowserDigest: digest, InvitationDigest: invitation})
	if err != nil {
		return StartResult{}, failedFlow("state_unavailable")
	}
	return StartResult{RedirectURL: authorization.URL, BrowserToken: token, ExpiresAt: expires}, nil
}

// Complete reports consumption separately so a stale callback cannot clear a
// newer browser binding. A consumed flow is never exchanged again.
func (s *Service) Complete(ctx context.Context, slug, state, code, responseIssuer, browser string, ip netip.Addr, userAgent string) (auth.LoginResult, bool, error) {
	if !ip.IsValid() || ip.Zone() != "" || len(userAgent) > 1024 {
		return auth.LoginResult{}, false, failedFlow("callback")
	}
	digest, err := Digest(browser)
	if err != nil {
		return auth.LoginResult{}, false, failedFlow("state_invalid")
	}
	// Consumption commits before any code exchange. A failed exchange or later
	// admission can only be retried by starting a new authorization flow.
	flow, err := s.repository.ConsumeOIDCFlow(ctx, slug, state, digest)
	if err != nil {
		return auth.LoginResult{}, false, failedFlow("state_invalid")
	}
	if code == "" || len(code) > 16384 || responseIssuer != "" && responseIssuer != flow.Provider.Config.IssuerURL {
		return auth.LoginResult{}, true, failedFlow("callback")
	}
	protocol, err := s.protocol(ctx, flow.Provider)
	if err != nil {
		return auth.LoginResult{}, true, failedFlow("discovery_failed")
	}
	assertion, err := protocol.Complete(ctx, state, code, flow.State)
	if err != nil {
		reason := "token_invalid"
		if errors.Is(err, authoidc.ErrNonceMismatch) {
			reason = "nonce_invalid"
		} else if errors.Is(err, authoidc.ErrExchange) {
			reason = "exchange_failed"
		} else if errors.Is(err, authoidc.ErrInvalidState) {
			reason = "state_invalid"
		}
		return auth.LoginResult{}, true, failedFlow(reason)
	}
	var claims struct {
		Email    string          `json:"email"`
		Verified json.RawMessage `json:"email_verified"`
	}
	// A bound subject does not require email or a verified-email claim. Malformed
	// email fields must not turn into verified data for an invitation claim.
	verified := false
	if assertion.Claims(&claims) == nil {
		verified = bytes.Equal(bytes.TrimSpace(claims.Verified), []byte("true"))
	}
	result, err := s.sessions.LoginExternal(ctx, auth.ExternalIdentity{FlowID: flow.ID, ProviderID: flow.Provider.ID, ProviderRevision: flow.Provider.Revision, Issuer: assertion.ProviderIssuer, Subject: assertion.Subject, Email: claims.Email, EmailVerified: verified}, ip, userAgent)
	if err != nil {
		reason := "admission_unavailable"
		if errors.Is(err, auth.ErrInvalidCredentials) {
			reason = "admission_denied"
		}
		return auth.LoginResult{}, true, failedFlow(reason)
	}
	return result, true, nil
}

func (s *Service) Failed(ctx context.Context, ip netip.Addr, reason string) error {
	return s.repository.SSOFailed(ctx, ip, reason)
}
