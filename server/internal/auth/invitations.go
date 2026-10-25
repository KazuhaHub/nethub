package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInviteInvalid = errors.New("invitation is unavailable")
	ErrWeakPassword  = errors.New("password does not meet the account policy")
)

// ValidateNewPassword is shared by bootstrap and invitation acceptance.
func ValidateNewPassword(password string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 15 || len(password) > MaxPasswordBytes || strings.ContainsAny(password, "\r\n\x00") {
		return ErrWeakPassword
	}
	return nil
}

type InvitationProvider struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Kind        string `json:"kind"`
}

type InvitationInfo struct {
	Email           string               `json:"email"`
	Role            string               `json:"role"`
	ExpiresAt       time.Time            `json:"expires_at"`
	PasswordAllowed bool                 `json:"password_allowed"`
	Providers       []InvitationProvider `json:"providers"`
}

// InvitationRepository consumes the invitation in the same transaction as the
// user, first session and audit. It must refuse existing accounts and restrictions.
type InvitationRepository interface {
	AcceptInvitation(context.Context, []byte, string, SessionRecord) (SessionRecord, error)
}

// InvitationDigest admits only the canonical 32-byte bearer format.
func InvitationDigest(token string) ([]byte, error) {
	digest, err := tokenHash(token)
	if err != nil {
		return nil, ErrInviteInvalid
	}
	return digest, nil
}

func (s *Service) AcceptInvitation(ctx context.Context, token, password string, ip netip.Addr, userAgent string) (LoginResult, error) {
	if !ip.IsValid() || ip.Zone() != "" || len(userAgent) > 1024 {
		return LoginResult{}, ErrInviteInvalid
	}
	digest, err := InvitationDigest(token)
	if limited := s.inviteLimits.Allow(ip, hex.EncodeToString(digest), time.Now()); limited != nil {
		return LoginResult{}, limited
	}
	if err != nil {
		return LoginResult{}, err
	}
	if err = ValidateNewPassword(password); err != nil {
		return LoginResult{}, err
	}
	repository, ok := s.repository.(InvitationRepository)
	if !ok {
		return LoginResult{}, ErrUnavailable
	}
	if ctx.Err() != nil {
		return LoginResult{}, ErrUnavailable
	}
	select {
	case s.workers <- struct{}{}:
		defer func() { <-s.workers }()
	default:
		return LoginResult{}, ErrBusy
	}
	hash, err := HashPassword(password)
	if err != nil {
		return LoginResult{}, ErrUnavailable
	}
	result, err := s.establishSession(ctx, ip, userAgent, func(record SessionRecord) (SessionRecord, error) {
		return repository.AcceptInvitation(ctx, digest, hash, record)
	})
	if errors.Is(err, ErrInviteInvalid) {
		return LoginResult{}, ErrInviteInvalid
	}
	if err != nil {
		return LoginResult{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) establishSession(ctx context.Context, ip netip.Addr, userAgent string, create func(SessionRecord) (SessionRecord, error)) (LoginResult, error) {
	if ctx.Err() != nil {
		return LoginResult{}, ErrUnavailable
	}
	token, err := newToken()
	if err != nil {
		return LoginResult{}, ErrUnavailable
	}
	digest, _ := tokenHash(token)
	csrf := csrfFor(token)
	now := time.Now().UTC()
	record, err := create(SessionRecord{TokenHash: digest, CSRFHash: csrfHash(csrf), CreatedAt: now, ExpiresAt: now.Add(s.config.AbsoluteTimeout), IP: ip.Unmap(), UserAgent: userAgent})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Session: Session{User: record.User, CSRFToken: csrf, ExpiresAt: record.ExpiresAt}, Token: token}, nil
}
