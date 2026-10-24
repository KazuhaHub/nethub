package web

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

func (s *Server) requestDisconnect(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, _, ok := s.mutation(w, r)
	if !ok {
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix+"/devices/"), "/disconnect")
	if !uuidPattern.MatchString(id) || r.URL.RawQuery != "" {
		writeError(w, r, 400, "invalid_request", "A canonical device ID is required")
		return
	}
	var input struct{}
	if !readJSON(w, r, &input) || s.rateFailure(w, r, s.disconnectLimits.Allow(ip, session.User.ID, time.Now())) {
		return
	}
	result, err := s.repository.RequestDisconnect(r.Context(), session.User.ID, id, ip.Unmap())
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeError(w, r, 401, "unauthenticated", "Sign in to continue")
		return
	}
	if errors.Is(err, ErrDeviceUnavailable) {
		writeError(w, r, 404, "not_found", "Device unavailable")
		return
	}
	if errors.Is(err, ErrDeviceNotRevoked) {
		writeError(w, r, 409, "device_not_revoked", "Revoke this enrollment before requesting disconnection")
		return
	}
	if err != nil || !uuidPattern.MatchString(result.RequestID) || result.RequestedAt.IsZero() || result.State != "pending" && result.State != "armed" ||
		result.State == "armed" && (result.ArmedAt == nil || result.ArmedAt.IsZero()) || result.State == "pending" && result.ArmedAt != nil {
		s.internal(w, r, "request disconnect")
		return
	}
	writeJSON(w, r, 200, result)
}
