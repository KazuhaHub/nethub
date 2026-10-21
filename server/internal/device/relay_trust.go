package device

import (
	"context"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

type RelayTrustRepository interface {
	Health(context.Context) error
	Current(context.Context, Credential, string) (*relaytrust.Generation, error)
	AcknowledgeReport(context.Context, Credential, string, relaytrust.Report) (time.Time, error)
}

type RelayTrustService struct {
	lifecycle  *Service
	repository RelayTrustRepository
}

func NewRelayTrust(lifecycle *Service, repository RelayTrustRepository) (*RelayTrustService, error) {
	if lifecycle == nil || repository == nil {
		return nil, ErrUnavailable
	}
	return &RelayTrustService{lifecycle: lifecycle, repository: repository}, nil
}

func (s *RelayTrustService) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.repository.Health(ctx)
}

func (s *RelayTrustService) Settings(ctx context.Context, input protocol.Identity, secret string, ip netip.Addr) (protocol.RelayTrustSettings, error) {
	if err := protocol.ValidateRelayTrustIdentity(input); err != nil {
		return protocol.RelayTrustSettings{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, credential, release, err := s.lifecycle.authenticateDevice(ctx, input, secret, ip)
	if err != nil {
		return protocol.RelayTrustSettings{}, err
	}
	defer release()
	generation, err := s.repository.Current(ctx, credential, input.DeviceID)
	if err != nil {
		return protocol.RelayTrustSettings{}, err
	}
	result := protocol.RelayTrustSettings{Identity: protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: input.DeviceID}}
	if generation != nil {
		bundle := generation.Bundle()
		if bundle == nil || !bundle.ValidAt(s.lifecycle.now()) || generation.ServerName != s.lifecycle.relay.ServerName {
			return protocol.RelayTrustSettings{}, ErrUnavailable
		}
		start, end := bundle.Window()
		result.Desired = &protocol.RelayTrustGeneration{ID: generation.ID, Generation: generation.Number, ServerName: generation.ServerName, CAPEM: bundle.PEM(), Fingerprint: bundle.Fingerprint(), PublishedAt: generation.PublishedAt.UTC().Format(protocol.CertificateTimeLayout), NotBefore: start.UTC().Format(protocol.CertificateTimeLayout), ValidUntil: end.UTC().Format(protocol.CertificateTimeLayout)}
	}
	return result, nil
}

func (s *RelayTrustService) Applied(ctx context.Context, input protocol.RelayTrustAppliedRequest, secret string, ip netip.Addr) (protocol.RelayTrustAppliedResponse, error) {
	if err := input.Validate(); err != nil {
		return protocol.RelayTrustAppliedResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, credential, release, err := s.lifecycle.authenticateDevice(ctx, input.Identity, secret, ip)
	if err != nil {
		return protocol.RelayTrustAppliedResponse{}, err
	}
	defer release()
	stamp, err := s.repository.AcknowledgeReport(ctx, credential, input.DeviceID, input.Report())
	if err != nil {
		return protocol.RelayTrustAppliedResponse{}, err
	}
	input.AgentProtocolVersion = protocol.Version
	result := protocol.RelayTrustAppliedResponse{RelayTrustAppliedRequest: input, Accepted: true, AcceptedAt: stamp.UTC().Format(protocol.CertificateTimeLayout)}
	if result.Validate() != nil {
		return protocol.RelayTrustAppliedResponse{}, ErrUnavailable
	}
	return result, nil
}
