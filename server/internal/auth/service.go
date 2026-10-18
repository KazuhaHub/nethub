package auth

import (
	"context"
	"crypto/hmac"
	"errors"
	"net/mail"
	"net/netip"
	"strings"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthenticated    = errors.New("unauthenticated")
	ErrUnavailable        = errors.New("authentication unavailable")
	ErrBusy               = errors.New("password verification busy")
)

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type Candidate struct {
	User
	PasswordHash string `json:"-"`
	Disabled     bool   `json:"-"`
}

type SessionRecord struct {
	User
	TokenHash, CSRFHash  []byte `json:"-"`
	CreatedAt, ExpiresAt time.Time
	IP                   netip.Addr
	UserAgent            string
}

// Repository is bound to the deployment tenant. Session creation must recheck
// the verified password and active user atomically; lookup must enforce idle
// and absolute expiry and reload current role/disable state on every request.
type Repository interface {
	PasswordCandidate(context.Context, string) (Candidate, error)
	CreateSession(context.Context, Candidate, SessionRecord) (SessionRecord, error)
	LookupSession(context.Context, []byte, time.Duration) (SessionRecord, error)
	DeleteSession(context.Context, []byte) error
}

type Session struct {
	User      User      `json:"user"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"session_expires_at"`
}

type LoginResult struct {
	Session
	Token string `json:"-"`
}

type Config struct {
	IdleTimeout, AbsoluteTimeout time.Duration
}

type Service struct {
	repository Repository
	config     Config
	dummyHash  string
	workers    chan struct{}
	limits     *loginLimiter
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("authentication repository is required")
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 30 * time.Minute
	}
	if config.AbsoluteTimeout == 0 {
		config.AbsoluteTimeout = 12 * time.Hour
	}
	if config.IdleTimeout < time.Second || config.AbsoluteTimeout < config.IdleTimeout || config.AbsoluteTimeout > 7*24*time.Hour {
		return nil, errors.New("invalid session timeouts")
	}
	dummy, err := newToken()
	if err != nil {
		return nil, err
	}
	hash, err := HashPassword(dummy)
	if err != nil {
		return nil, err
	}
	return &Service{repository: repository, config: config, dummyHash: hash, workers: make(chan struct{}, 2), limits: newLoginLimiter(10000)}, nil
}

func NormalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	parsed, err := mail.ParseAddress(email)
	if err != nil || len(email) > 320 || parsed.Address != email || parsed.Name != "" || strings.ContainsAny(email, "\r\n\x00") {
		return "", ErrInvalidCredentials
	}
	return email, nil
}

func (s *Service) Login(ctx context.Context, email, password string, ip netip.Addr, userAgent string) (LoginResult, error) {
	if !ip.IsValid() || ip.Zone() != "" || len(userAgent) > 1024 {
		return LoginResult{}, ErrInvalidCredentials
	}
	if len(email) > 320 {
		return LoginResult{}, ErrInvalidCredentials
	}
	if err := s.limits.allow(ip, strings.ToLower(strings.TrimSpace(email)), time.Now()); err != nil {
		return LoginResult{}, err
	}
	select {
	case <-ctx.Done():
		return LoginResult{}, ErrUnavailable
	default:
	}
	select {
	case s.workers <- struct{}{}:
		defer func() { <-s.workers }()
	default:
		return LoginResult{}, ErrBusy
	}
	canonical, err := NormalizeEmail(email)
	candidate := Candidate{}
	if err == nil {
		candidate, err = s.repository.PasswordCandidate(ctx, canonical)
		if err != nil && !errors.Is(err, ErrInvalidCredentials) {
			return LoginResult{}, ErrUnavailable
		}
	}
	hash := candidate.PasswordHash
	if hash == "" {
		hash = s.dummyHash
	}
	valid, verifyErr := VerifyPassword(hash, password)
	if verifyErr != nil {
		// Malformed stored hashes still pay the normal verification cost.
		VerifyPassword(s.dummyHash, "invalid-credential-probe")
	}
	if err != nil || verifyErr != nil || !valid || candidate.Disabled || candidate.PasswordHash == "" {
		return LoginResult{}, ErrInvalidCredentials
	}
	token, err := newToken()
	if err != nil {
		return LoginResult{}, ErrUnavailable
	}
	digest, _ := tokenHash(token)
	csrf := csrfFor(token)
	now := time.Now().UTC()
	record, err := s.repository.CreateSession(ctx, candidate, SessionRecord{TokenHash: digest, CSRFHash: csrfHash(csrf), CreatedAt: now, ExpiresAt: now.Add(s.config.AbsoluteTimeout), IP: ip.Unmap(), UserAgent: userAgent})
	if errors.Is(err, ErrInvalidCredentials) {
		return LoginResult{}, err
	}
	if err != nil {
		return LoginResult{}, ErrUnavailable
	}
	return LoginResult{Session: Session{User: record.User, CSRFToken: csrf, ExpiresAt: record.ExpiresAt}, Token: token}, nil
}

func (s *Service) Authenticate(ctx context.Context, token string) (Session, error) {
	digest, err := tokenHash(token)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	record, err := s.repository.LookupSession(ctx, digest, s.config.IdleTimeout)
	if errors.Is(err, ErrUnauthenticated) {
		return Session{}, err
	}
	if err != nil {
		return Session{}, ErrUnavailable
	}
	csrf := csrfFor(token)
	if !hmac.Equal(record.CSRFHash, csrfHash(csrf)) {
		return Session{}, ErrUnauthenticated
	}
	return Session{User: record.User, CSRFToken: csrf, ExpiresAt: record.ExpiresAt}, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	digest, err := tokenHash(token)
	if err != nil {
		return ErrUnauthenticated
	}
	if err = s.repository.DeleteSession(ctx, digest); err != nil {
		return ErrUnavailable
	}
	return nil
}
