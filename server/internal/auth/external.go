package auth

import (
	"context"
	"errors"
	"net/netip"
	"unicode/utf8"
)

// ExternalIdentity comes only from a verified protocol assertion and a consumed
// browser flow. No HTTP endpoint accepts this structure from a client.
type ExternalIdentity struct {
	FlowID, ProviderID     string
	ProviderRevision       int64
	Issuer, Subject, Email string
	EmailVerified          bool
}

func (ExternalIdentity) String() string     { return "ExternalIdentity(verified)" }
func (v ExternalIdentity) GoString() string { return v.String() }

type ExternalRepository interface {
	CreateExternalSession(context.Context, ExternalIdentity, SessionRecord) (SessionRecord, error)
}

func (s *Service) LoginExternal(ctx context.Context, identity ExternalIdentity, ip netip.Addr, userAgent string) (LoginResult, error) {
	if !ip.IsValid() || ip.Zone() != "" || len(userAgent) > 1024 || identity.FlowID == "" || identity.ProviderID == "" || identity.ProviderRevision < 1 || identity.Issuer == "" || len(identity.Issuer) > 2048 || identity.Subject == "" || len(identity.Subject) > 4096 || !utf8.ValidString(identity.Subject) {
		return LoginResult{}, ErrInvalidCredentials
	}
	repository, ok := s.repository.(ExternalRepository)
	if !ok {
		return LoginResult{}, ErrUnavailable
	}
	result, err := s.establishSession(ctx, ip, userAgent, func(record SessionRecord) (SessionRecord, error) {
		return repository.CreateExternalSession(ctx, identity, record)
	})
	if errors.Is(err, ErrInvalidCredentials) {
		return LoginResult{}, err
	}
	if err != nil {
		return LoginResult{}, ErrUnavailable
	}
	return result, nil
}
