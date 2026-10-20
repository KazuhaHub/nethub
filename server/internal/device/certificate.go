package device

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

type CertificateRepository interface {
	Health(context.Context) error
	Settings(context.Context, Credential, string) (guicert.Assignment, *guicert.StoredRequest, error)
	Admit(context.Context, Credential, string, []byte) (guicert.StoredRequest, error)
	Issued(context.Context, Credential, string, string, string) (guicert.StoredRequest, *guicert.IssuedCertificate, error)
	Acknowledge(context.Context, Credential, guicert.ApplicationReport) (time.Time, error)
}

func (s *CertificateService) Applied(ctx context.Context, input protocol.CertificateAppliedRequest, secret string, ip netip.Addr) (protocol.CertificateAppliedResponse, error) {
	if err := input.Validate(); err != nil {
		return protocol.CertificateAppliedResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, credential, release, err := s.lifecycle.authenticateDevice(ctx, input.Identity, secret, ip)
	if err != nil {
		return protocol.CertificateAppliedResponse{}, err
	}
	defer release()
	accepted, err := s.repository.Acknowledge(ctx, credential, guicert.ApplicationReport{DeviceID: input.DeviceID, RequestID: input.RequestID,
		RequestFingerprint: input.CSRFingerprint, GenerationID: input.GenerationID, Generation: input.Generation, Fingerprint: input.LeafFingerprint})
	if err != nil {
		return protocol.CertificateAppliedResponse{}, err
	}
	input.AgentProtocolVersion = protocol.Version
	result := protocol.CertificateAppliedResponse{CertificateAppliedRequest: input, Accepted: true, AcceptedAt: accepted.UTC().Format(protocol.CertificateTimeLayout)}
	if accepted.IsZero() || result.Validate() != nil {
		return protocol.CertificateAppliedResponse{}, ErrUnavailable
	}
	return result, nil
}

// CertificateService shares lifecycle authentication and its bounded Argon2 pool.
// Configuring admission does not configure an issuer or contact a CA.
type CertificateService struct {
	lifecycle  *Service
	repository CertificateRepository
}

func NewCertificates(lifecycle *Service, repository CertificateRepository) (*CertificateService, error) {
	if lifecycle == nil || repository == nil {
		return nil, ErrUnavailable
	}
	return &CertificateService{lifecycle: lifecycle, repository: repository}, nil
}

func (s *CertificateService) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.repository.Health(ctx)
}

func certificateResponse(identity protocol.Identity, assignment guicert.Assignment, record *guicert.StoredRequest) (protocol.CertificateSettings, error) {
	result := protocol.CertificateSettings{Identity: protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: identity.DeviceID}, AssignedHost: assignment.Host, GUIKeyFingerprint: assignment.KeyFingerprint}
	if record != nil {
		if record.DeviceID != identity.DeviceID || record.AssignedHost != assignment.Host {
			return protocol.CertificateSettings{}, ErrUnavailable
		}
		bound, err := guicert.ValidatePublicKey(record.PublicKey)
		if err != nil || bound.Fingerprint != assignment.KeyFingerprint {
			return protocol.CertificateSettings{}, ErrUnavailable
		}
		result.Request = &protocol.CertificateRecord{RequestID: record.ID, CSRDER: base64.StdEncoding.EncodeToString(record.DER), CSRFingerprint: record.Fingerprint, CreatedAt: record.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000Z")}
	}
	if err := result.Validate(); err != nil {
		return protocol.CertificateSettings{}, ErrUnavailable
	}
	return result, nil
}

func (s *CertificateService) Settings(ctx context.Context, identity protocol.Identity, secret string, ip netip.Addr) (protocol.CertificateSettings, error) {
	if err := protocol.ValidateCertificateIdentity(identity); err != nil {
		return protocol.CertificateSettings{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, credential, release, err := s.lifecycle.authenticateDevice(ctx, identity, secret, ip)
	if err != nil {
		return protocol.CertificateSettings{}, err
	}
	defer release()
	assignment, record, err := s.repository.Settings(ctx, credential, identity.DeviceID)
	if err != nil {
		return protocol.CertificateSettings{}, err
	}
	return certificateResponse(identity, assignment, record)
}

func (s *CertificateService) Submit(ctx context.Context, input protocol.CertificateSubmit, secret string, ip netip.Addr) (protocol.CertificateSettings, error) {
	if err := input.Validate(); err != nil {
		return protocol.CertificateSettings{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, credential, release, err := s.lifecycle.authenticateDevice(ctx, input.Identity, secret, ip)
	if err != nil {
		return protocol.CertificateSettings{}, err
	}
	defer release()
	der, err := protocol.CertificateDER(input.CSRDER)
	if err != nil {
		return protocol.CertificateSettings{}, err
	}
	record, err := s.repository.Admit(ctx, credential, input.DeviceID, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if err != nil {
		return protocol.CertificateSettings{}, err
	}
	if !bytes.Equal(record.DER, der) {
		return protocol.CertificateSettings{}, ErrUnavailable
	}
	bound, err := guicert.ValidatePublicKey(record.PublicKey)
	if err != nil {
		return protocol.CertificateSettings{}, ErrUnavailable
	}
	return certificateResponse(input.Identity, guicert.Assignment{Host: record.AssignedHost, KeyFingerprint: bound.Fingerprint}, &record)
}

func (s *CertificateService) Issued(ctx context.Context, input protocol.CertificateIssuedRequest, secret string, ip netip.Addr) (protocol.CertificateDelivery, error) {
	if err := input.Validate(); err != nil {
		return protocol.CertificateDelivery{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, credential, release, err := s.lifecycle.authenticateDevice(ctx, input.Identity, secret, ip)
	if err != nil {
		return protocol.CertificateDelivery{}, err
	}
	defer release()
	record, generation, err := s.repository.Issued(ctx, credential, input.DeviceID, input.RequestID, input.CSRFingerprint)
	if err != nil {
		return protocol.CertificateDelivery{}, err
	}
	if record.ID != input.RequestID || record.Fingerprint != input.CSRFingerprint {
		return protocol.CertificateDelivery{}, ErrUnavailable
	}
	key, err := guicert.ValidatePublicKey(record.PublicKey)
	if err != nil {
		return protocol.CertificateDelivery{}, ErrUnavailable
	}
	settings, err := certificateResponse(input.Identity, guicert.Assignment{Host: record.AssignedHost, KeyFingerprint: key.Fingerprint}, &record)
	if err != nil {
		return protocol.CertificateDelivery{}, err
	}
	result := protocol.CertificateDelivery{CertificateSettings: settings}
	if generation != nil {
		result.Issued = &protocol.CertificateGeneration{ID: generation.ID, Generation: generation.Generation, ChainPEM: string(generation.PEM), LeafFingerprint: generation.Fingerprint,
			NotBefore: generation.NotBefore.UTC().Format(protocol.CertificateTimeLayout), NotAfter: generation.NotAfter.UTC().Format(protocol.CertificateTimeLayout),
			ValidUntil: generation.ValidUntil.UTC().Format(protocol.CertificateTimeLayout), RenewAfter: generation.RenewAfter.UTC().Format(protocol.CertificateTimeLayout)}
	}
	if result.Validate() != nil {
		return protocol.CertificateDelivery{}, ErrUnavailable
	}
	return result, nil
}
