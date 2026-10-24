package web

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

func (s *Server) openDevice(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, _, ok := s.mutation(w, r)
	if !ok {
		return
	}
	device := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix+"/devices/"), "/open")
	var input struct{}
	if !uuidPattern.MatchString(device) || r.URL.RawQuery != "" {
		writeError(w, r, 400, "invalid_request", "A canonical device ID is required")
		return
	}
	if !readJSON(w, r, &input) || s.rateFailure(w, r, s.openLimits.Allow(ip, session.User.ID, time.Now())) {
		return
	}
	result, err := s.repository.OpenDevice(r.Context(), session.User.ID, device, ip.Unmap())
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeError(w, r, 401, "unauthenticated", "Sign in to continue")
		return
	}
	if errors.Is(err, ErrDeviceUnavailable) {
		writeError(w, r, 404, "not_found", "Device unavailable")
		return
	}
	if errors.Is(err, ErrDeviceRevoked) {
		writeError(w, r, 409, "device_revoked", "This device has been revoked")
		return
	}
	if err != nil {
		s.internal(w, r, "open device")
		return
	}
	host := result.Subdomain + "." + s.deviceDomain
	if !hostnameLabel.MatchString(result.Subdomain) || len(host) > 253 || host == s.consoleHostname || result.ExpiresAt.IsZero() {
		s.internal(w, r, "open device URL")
		return
	}
	result.URL = "https://" + host + ":8443"
	writeJSON(w, r, 200, result)
}
