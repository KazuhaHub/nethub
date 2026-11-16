package device

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

var ErrReconcileAuditConflict = errors.New("reconcile audit event identity already bound")

type ReconcileAuditRepository interface {
	RecordReconcileEvents(context.Context, Credential, protocol.ReconcileAuditRequest) (bool, error)
}

func (s *Service) ReportReconcileEvents(ctx context.Context, request protocol.ReconcileAuditRequest, secret string, ip netip.Addr) (protocol.ReconcileAuditResponse, error) {
	if err := request.Validate(); err != nil {
		return protocol.ReconcileAuditResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	repository, credential, release, err := s.authenticateDevice(ctx, request.Identity, secret, ip)
	if err != nil {
		return protocol.ReconcileAuditResponse{}, err
	}
	defer release()
	sink, ok := repository.(ReconcileAuditRepository)
	if !ok {
		return protocol.ReconcileAuditResponse{}, ErrUnavailable
	}
	revoked, err := sink.RecordReconcileEvents(ctx, credential, request)
	if err != nil {
		return protocol.ReconcileAuditResponse{}, err
	}
	ids := make([]string, len(request.Events))
	for i, event := range request.Events {
		ids[i] = event.EventID
	}
	return protocol.ReconcileAuditResponse{Identity: protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: request.DeviceID}, Accepted: true, Revoked: revoked, EventIDs: ids}, nil
}
