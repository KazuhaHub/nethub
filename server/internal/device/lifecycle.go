package device

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

type Credential struct {
	TenantID string
	Hash     string `json:"-"`
}

// LifecycleRepository rechecks the authenticated hash under the mutation lock.
type LifecycleRepository interface {
	DeviceCredential(context.Context, string) (Credential, error)
	ReportDevice(context.Context, Credential, protocol.StatusRequest) (bool, error)
	UnenrollDevice(context.Context, Credential, protocol.Identity, netip.Addr) error
}

func (s *Service) authenticateDevice(ctx context.Context, identity protocol.Identity, secret string, ip netip.Addr) (LifecycleRepository, Credential, func(), error) {
	if err := identity.Validate(); err != nil {
		return nil, Credential{}, nil, err
	}
	if !protocol.ValidDeviceSecret(secret) || !ip.IsValid() || ip.Zone() != "" {
		return nil, Credential{}, nil, ErrDenied
	}
	if err := s.admitLifecycle(ip, s.now()); err != nil {
		return nil, Credential{}, nil, err
	}
	select {
	case s.workers <- struct{}{}:
	default:
		return nil, Credential{}, nil, ErrBusy
	}
	release := func() { <-s.workers }
	repository, ok := s.repository.(LifecycleRepository)
	if !ok {
		release()
		return nil, Credential{}, nil, ErrUnavailable
	}
	credential, err := repository.DeviceCredential(ctx, identity.DeviceID)
	if err != nil && !errors.Is(err, ErrDenied) {
		release()
		return nil, Credential{}, nil, ErrUnavailable
	}
	hash := credential.Hash
	if errors.Is(err, ErrDenied) {
		hash = s.deviceDummyHash
	}
	valid, verifyErr := auth.VerifyPassword(hash, secret)
	if verifyErr != nil {
		_, _ = auth.VerifyPassword(s.deviceDummyHash, secret)
	}
	if err != nil || verifyErr != nil || !valid {
		release()
		return nil, Credential{}, nil, ErrDenied
	}
	if ctx.Err() != nil {
		release()
		return nil, Credential{}, nil, ErrUnavailable
	}
	return repository, credential, release, nil
}

// Health reports use a separate bounded budget so they cannot consume enrollment slots.
func (s *Service) admitLifecycle(ip netip.Addr, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !now.Before(s.lifecycleSweep) {
		for key, value := range s.lifecycleWindows {
			if !now.Before(value.started.Add(time.Minute)) {
				delete(s.lifecycleWindows, key)
			}
		}
		s.lifecycleSweep = now.Add(time.Minute)
	}
	ip = ip.Unmap()
	value, exists := s.lifecycleWindows[ip]
	if !exists && len(s.lifecycleWindows) >= 10000 {
		return ErrLimited
	}
	if !now.Before(value.started.Add(time.Minute)) {
		value = window{started: now}
	}
	if value.count >= 120 {
		return ErrLimited
	}
	value.count++
	s.lifecycleWindows[ip] = value
	return nil
}

func (s *Service) Report(ctx context.Context, request protocol.StatusRequest, secret string, ip netip.Addr) (protocol.StatusResponse, error) {
	if err := request.Validate(); err != nil {
		return protocol.StatusResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	repository, credential, release, err := s.authenticateDevice(ctx, request.Identity, secret, ip)
	if err != nil {
		return protocol.StatusResponse{}, err
	}
	defer release()
	revoked, err := repository.ReportDevice(ctx, credential, request)
	if err != nil {
		return protocol.StatusResponse{}, err
	}
	return protocol.StatusResponse{Identity: protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: request.DeviceID}, Accepted: true, Revoked: revoked}, nil
}

func (s *Service) Unenroll(ctx context.Context, request protocol.Identity, secret string, ip netip.Addr) (protocol.UnenrollResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	repository, credential, release, err := s.authenticateDevice(ctx, request, secret, ip)
	if err != nil {
		return protocol.UnenrollResponse{}, err
	}
	defer release()
	if err := repository.UnenrollDevice(ctx, credential, request, ip); err != nil {
		return protocol.UnenrollResponse{}, err
	}
	return protocol.UnenrollResponse{Identity: protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: request.DeviceID}, Revoked: true}, nil
}
