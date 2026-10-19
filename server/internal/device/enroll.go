// Package device implements admission to the platform-neutral device API.
package device

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/claim"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

var ErrDenied = errors.New("enrollment failed")
var ErrUnavailable = errors.New("device enrollment unavailable")
var ErrBusy = errors.New("device enrollment busy")
var ErrLimited = errors.New("device enrollment rate limited")

var hostname = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
var subdomain = regexp.MustCompile(`^[a-z0-9]{8}$`)
var reserved = map[string]bool{"admin": true, "www": true, "api": true, "auth": true,
	"login": true, "logout": true, "console": true, "static": true, "assets": true,
	"health": true, "healthz": true, "metrics": true, "settings": true,
	"register": true, "security": true}

type RelayConfig struct {
	Address, ServerName string
	Port                uint16
	FRPToken            string `json:"-"`
	CAPEM               string
}

type Metadata struct {
	ProtocolVersion, Platform, PlatformVersion, AgentVersion, Hostname string
	Capabilities                                                       []string
	ClusterHint                                                        bool
}

type Registration struct {
	Metadata
	TokenHash  [32]byte `json:"-"`
	SecretHash string   `json:"-"`
	Candidates []string
	SourceIP   netip.Addr
}

type Assignment struct {
	ID, TenantID, OwnerID, Subdomain, Claim string
	IssuedAt                                time.Time
}

// Register must consume, insert, sign and append audit in one transaction.
type Repository interface {
	Health(context.Context) error
	Register(context.Context, Registration, func(Assignment) (string, error)) (Assignment, error)
}

func (r Registration) Validate() error {
	input := protocol.EnrollRequest{AgentProtocolVersion: r.ProtocolVersion,
		Platform: r.Platform, PlatformVersion: r.PlatformVersion, AgentVersion: r.AgentVersion,
		Hostname: r.Hostname, Capabilities: r.Capabilities, ClusterHint: r.ClusterHint}
	if err := input.ValidateMetadata(); err != nil {
		return err
	}
	if !r.SourceIP.IsValid() || r.SourceIP.Zone() != "" || len(r.SecretHash) < 64 || len(r.SecretHash) > 256 ||
		!strings.HasPrefix(r.SecretHash, "$argon2id$") || len(r.Candidates) < 1 || len(r.Candidates) > 8 {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for _, name := range r.Candidates {
		if !subdomain.MatchString(name) || reserved[name] || seen[name] {
			return ErrUnavailable
		}
		seen[name] = true
	}
	return nil
}

type window struct {
	started time.Time
	count   int
}

type Service struct {
	repository       Repository
	signer           *claim.Keyring
	relay            RelayConfig
	certs            []*x509.Certificate
	workers          chan struct{}
	entropy          io.Reader
	hash             func(string) (string, error)
	now              func() time.Time
	mu               sync.Mutex
	windows          map[netip.Addr]window
	sweepAfter       time.Time
	deviceDummyHash  string
	lifecycleWindows map[netip.Addr]window
	lifecycleSweep   time.Time
}

func (s *Service) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if !s.trustValid(s.now()) || s.repository.Health(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}

func New(repository Repository, signer *claim.Keyring, relay RelayConfig) (*Service, error) {
	if repository == nil || signer == nil || relay.Port == 0 || len(relay.Address) > 253 ||
		len(relay.ServerName) > 253 || !hostname.MatchString(relay.ServerName) ||
		len(relay.CAPEM) > 32768 || len(relay.FRPToken) != 64 {
		return nil, ErrUnavailable
	}
	ip, addressError := netip.ParseAddr(relay.Address)
	if (addressError != nil && !hostname.MatchString(relay.Address)) || (addressError == nil && ip.Zone() != "") {
		return nil, ErrUnavailable
	}
	token, err := hex.DecodeString(relay.FRPToken)
	if err != nil || len(token) != 32 || hex.EncodeToString(token) != relay.FRPToken {
		return nil, ErrUnavailable
	}
	var certs []*x509.Certificate
	var canonicalPEM strings.Builder
	rest := strings.TrimSpace(relay.CAPEM)
	for rest != "" {
		if !strings.HasPrefix(rest, "-----BEGIN CERTIFICATE-----") || len(certs) >= 2 {
			return nil, ErrUnavailable
		}
		const endMarker = "-----END CERTIFICATE-----"
		end := strings.Index(rest, endMarker)
		if end < 0 {
			return nil, ErrUnavailable
		}
		chunk, remaining := rest[:end+len(endMarker)], rest[end+len(endMarker):]
		if strings.Count(chunk, "-----BEGIN ") != 1 {
			return nil, ErrUnavailable
		}
		block, trailing := pem.Decode([]byte(chunk))
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || strings.TrimSpace(string(trailing)) != "" {
			return nil, ErrUnavailable
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.BasicConstraintsValid || !cert.IsCA ||
			len(cert.UnhandledCriticalExtensions) != 0 ||
			(cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0) || cert.CheckSignatureFrom(cert) != nil {
			return nil, ErrUnavailable
		}
		certs = append(certs, cert)
		canonicalPEM.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		rest = strings.TrimSpace(remaining)
	}
	if len(certs) == 0 || canonicalPEM.Len() > 32768 {
		return nil, ErrUnavailable
	}
	relay.CAPEM = canonicalPEM.String()
	dummy, err := auth.HashPassword("device-authentication-timing-probe")
	if err != nil {
		return nil, ErrUnavailable
	}
	service := &Service{repository: repository, signer: signer, relay: relay, certs: certs,
		workers: make(chan struct{}, 2), entropy: rand.Reader, hash: auth.HashPassword,
		now: time.Now, windows: make(map[netip.Addr]window), deviceDummyHash: dummy, lifecycleWindows: make(map[netip.Addr]window)}
	if !service.trustValid(service.now()) {
		return nil, ErrUnavailable
	}
	return service, nil
}

func (s *Service) trustValid(now time.Time) bool {
	for _, cert := range s.certs {
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return false
		}
	}
	return true
}

func (s *Service) admit(ip netip.Addr, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !now.Before(s.sweepAfter) {
		for key, value := range s.windows {
			if !now.Before(value.started.Add(time.Minute)) {
				delete(s.windows, key)
			}
		}
		s.sweepAfter = now.Add(time.Minute)
	}
	ip = ip.Unmap()
	value, exists := s.windows[ip]
	if !exists && len(s.windows) >= 10000 {
		return ErrLimited
	}
	if !now.Before(value.started.Add(time.Minute)) {
		value = window{started: now}
	}
	if value.count >= 10 {
		return ErrLimited
	}
	value.count++
	s.windows[ip] = value
	return nil
}

func randomCandidates(entropy io.Reader) ([]string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]string, 0, 8)
	seen := map[string]bool{}
	for attempts := 0; len(result) < 8 && attempts < 64; attempts++ {
		name := make([]byte, 0, 8)
		var octet [1]byte
		for budget := 0; len(name) < 8 && budget < 128; budget++ {
			if _, err := io.ReadFull(entropy, octet[:]); err != nil {
				return nil, ErrUnavailable
			}
			if octet[0] < 252 {
				name = append(name, alphabet[int(octet[0])%len(alphabet)])
			}
		}
		value := string(name)
		if len(name) != 8 {
			return nil, ErrUnavailable
		}
		if !reserved[value] && !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	if len(result) != 8 {
		return nil, ErrUnavailable
	}
	return result, nil
}

func (s *Service) Enroll(ctx context.Context, request protocol.EnrollRequest, ip netip.Addr) (protocol.EnrollResponse, error) {
	if err := request.Validate(); err != nil {
		return protocol.EnrollResponse{}, err
	}
	if !ip.IsValid() || ip.Zone() != "" {
		return protocol.EnrollResponse{}, protocol.ErrInvalidRequest
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	now := s.now()
	if ctx.Err() != nil || !s.trustValid(now) {
		return protocol.EnrollResponse{}, ErrUnavailable
	}
	if err := s.admit(ip, now); err != nil {
		return protocol.EnrollResponse{}, err
	}
	select {
	case s.workers <- struct{}{}:
		defer func() { <-s.workers }()
	default:
		return protocol.EnrollResponse{}, ErrBusy
	}
	var secret [32]byte
	if _, err := io.ReadFull(s.entropy, secret[:]); err != nil {
		return protocol.EnrollResponse{}, ErrUnavailable
	}
	rawSecret := base64.RawURLEncoding.EncodeToString(secret[:])
	hash, err := s.hash(rawSecret)
	if err != nil || ctx.Err() != nil {
		return protocol.EnrollResponse{}, ErrUnavailable
	}
	candidates, err := randomCandidates(s.entropy)
	if err != nil {
		return protocol.EnrollResponse{}, err
	}
	rawToken, _ := base64.RawURLEncoding.Strict().DecodeString(request.EnrollToken)
	record := Registration{TokenHash: sha256.Sum256(rawToken), SecretHash: hash,
		Candidates: candidates, SourceIP: ip.Unmap(), Metadata: Metadata{
			ProtocolVersion: request.AgentProtocolVersion, Platform: request.Platform,
			PlatformVersion: request.PlatformVersion, AgentVersion: request.AgentVersion,
			Hostname: request.Hostname, Capabilities: append([]string(nil), request.Capabilities...),
			ClusterHint: request.ClusterHint}}
	assigned, err := s.repository.Register(ctx, record, func(value Assignment) (string, error) {
		if ctx.Err() != nil || !s.trustValid(s.now()) {
			return "", ErrUnavailable
		}
		return s.signer.Issue(value.ID, value.Subdomain, value.TenantID, value.IssuedAt)
	})
	if err != nil {
		if errors.Is(err, ErrDenied) {
			return protocol.EnrollResponse{}, ErrDenied
		}
		return protocol.EnrollResponse{}, ErrUnavailable
	}
	return protocol.EnrollResponse{AgentProtocolVersion: protocol.Version,
		DeviceID: assigned.ID, DeviceSecret: rawSecret, FRPToken: s.relay.FRPToken,
		ServerAddr: s.relay.Address, ServerPort: s.relay.Port, ServerName: s.relay.ServerName,
		Subdomain: assigned.Subdomain, DomainClaim: assigned.Claim, RelayCAPEM: s.relay.CAPEM}, nil
}
