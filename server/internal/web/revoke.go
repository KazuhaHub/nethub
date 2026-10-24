package web

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, _, ok := s.mutation(w, r)
	if !ok {
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix+"/devices/"), "/revoke")
	if !uuidPattern.MatchString(id) || r.URL.RawQuery != "" {
		writeError(w, r, 400, "invalid_request", "A canonical device ID is required")
		return
	}
	var input struct{}
	if !readJSON(w, r, &input) || s.rateFailure(w, r, s.revokeLimits.Allow(ip, session.User.ID, time.Now())) {
		return
	}
	result, err := s.repository.RevokeDevice(r.Context(), session.User.ID, id, ip.Unmap())
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeError(w, r, 401, "unauthenticated", "Sign in to continue")
		return
	}
	if errors.Is(err, ErrDeviceUnavailable) {
		writeError(w, r, 404, "not_found", "Device unavailable")
		return
	}
	if err != nil || !result.Revoked || result.RevokedAt.IsZero() {
		s.internal(w, r, "revoke device")
		return
	}
	writeJSON(w, r, 200, result)
}
