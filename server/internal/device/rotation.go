package device

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

// RotationRecord contains no plaintext credential. CandidateDigest binds the
// high-entropy journal candidate to an immutable operation, not authentication.
var ErrRotationTrustChanged = errors.New("relay trust changed before credential rotation")

type RotationRecord struct {
	protocol.Identity
	OperationID           string
	CandidateDigest       [32]byte `json:"-"`
	SecretHash            string   `json:"-"`
	CandidateIsCurrent    bool
	ExpectedRelayCASHA256 string
	BootstrapCAPEM        string
	RelayServerName       string
	SourceIP              netip.Addr
}

func (r RotationRecord) Validate() error {
	if protocol.ValidateRotationIdentity(r.Identity) != nil || !protocol.ValidRotationOperationID(r.OperationID) ||
		!protocol.ValidRelayTrustDigest(r.ExpectedRelayCASHA256) || len(r.BootstrapCAPEM) < 1 || len(r.BootstrapCAPEM) > 32768 ||
		!r.SourceIP.IsValid() || r.SourceIP.Zone() != "" || !hostname.MatchString(r.RelayServerName) ||
		len(r.RelayServerName) > 253 || !strings.HasPrefix(r.SecretHash, "$argon2id$") ||
		len(r.SecretHash) < 64 || len(r.SecretHash) > 256 {
		return protocol.ErrInvalidRequest
	}
	return nil
}

type RotationRepository interface {
	RotateDevice(context.Context, Credential, RotationRecord, func(Assignment) (string, error)) (Assignment, error)
}

func (s *Service) Rotate(ctx context.Context, request protocol.RotateRequest, secret string, ip netip.Addr) (protocol.RotateResponse, error) {
	if err := request.Validate(); err != nil {
		return protocol.RotateResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, credential, release, err := s.authenticateDevice(ctx, request.Identity, secret, ip)
	if err != nil {
		return protocol.RotateResponse{}, err
	}
	defer release()
	repository, ok := s.repository.(RotationRepository)
	if !ok || !s.trustReady(ctx) {
		return protocol.RotateResponse{}, ErrUnavailable
	}
	same := hmac.Equal([]byte(secret), []byte(request.ReplacementSecret))
	hash := credential.Hash
	if !same {
		hash, err = s.hash(request.ReplacementSecret)
		if err != nil || ctx.Err() != nil {
			return protocol.RotateResponse{}, ErrUnavailable
		}
	}
	record := RotationRecord{Identity: request.Identity, OperationID: request.OperationID,
		CandidateDigest: sha256.Sum256([]byte(request.ReplacementSecret)), SecretHash: hash,
		ExpectedRelayCASHA256: request.ExpectedRelayCASHA256, BootstrapCAPEM: s.relay.CAPEM,
		CandidateIsCurrent: same, RelayServerName: s.relay.ServerName, SourceIP: ip.Unmap()}
	assigned, err := repository.RotateDevice(ctx, credential, record, func(value Assignment) (string, error) {
		if ctx.Err() != nil || value.ID != request.DeviceID || value.TenantID != credential.TenantID {
			return "", ErrUnavailable
		}
		if value.RelayCAPEM != "" {
			if _, err := relaytrust.Parse(value.RelayCAPEM, s.now()); err != nil {
				return "", ErrUnavailable
			}
			// trustReady observes live publication. An immutable replay bundle
			// may instead be the original unpublished bootstrap trust.
		} else if s.publishedTrustSeen.Load() || !s.trustValid(s.now()) {
			return "", ErrUnavailable
		}
		return s.signer.Issue(value.ID, value.Subdomain, value.TenantID, value.IssuedAt)
	})
	if err != nil {
		if errors.Is(err, ErrRotationTrustChanged) {
			return protocol.RotateResponse{}, ErrRotationTrustChanged
		}
		if errors.Is(err, ErrDenied) {
			return protocol.RotateResponse{}, ErrDenied
		}
		return protocol.RotateResponse{}, ErrUnavailable
	}
	publicTrust := s.relay.CAPEM
	if assigned.RelayCAPEM != "" {
		publicTrust = assigned.RelayCAPEM
	}
	return protocol.RotateResponse{OperationID: request.OperationID, EnrollResponse: protocol.EnrollResponse{
		AgentProtocolVersion: protocol.Version, DeviceID: assigned.ID, DeviceSecret: request.ReplacementSecret,
		FRPToken: s.relay.FRPToken, ServerAddr: s.relay.Address, ServerPort: s.relay.Port,
		ServerName: s.relay.ServerName, Subdomain: assigned.Subdomain, DomainClaim: assigned.Claim, RelayCAPEM: publicTrust}}, nil
}
