package web

import (
	"encoding/base64"
	"errors"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (s *Server) rateFailure(w http.ResponseWriter, r *http.Request, err error) bool {
	var limited *auth.RateLimitError
	seconds := 0
	if errors.As(err, &limited) {
		seconds = max(1, int(math.Ceil(limited.RetryAfter.Seconds())))
	}
	if errors.Is(err, auth.ErrBusy) {
		seconds = 1
	}
	if seconds == 0 {
		return false
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeError(w, r, 429, "rate_limited", "Too many attempts; try again later")
	return true
}

func (s *Server) login(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	if !s.origin.Check(r, true) {
		writeError(w, r, 403, "csrf_failed", "A matching console Origin is required")
		return
	}
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &input, "email", "password") {
		return
	}
	if input.Email == "" || input.Password == "" || len(input.Email) > 320 || len(input.Password) > auth.MaxPasswordBytes {
		writeError(w, r, 400, "invalid_request", "Email and password are required within supported limits")
		return
	}
	result, err := s.auth.Login(r.Context(), input.Email, input.Password, ip, r.UserAgent())
	if s.rateFailure(w, r, err) {
		return
	}
	if errors.Is(err, auth.ErrInvalidCredentials) {
		if auditErr := s.repository.LoginFailed(r.Context(), ip); auditErr != nil {
			s.internal(w, r, "login audit")
			return
		}
		writeError(w, r, 401, "invalid_credentials", "Sign-in failed")
		return
	}
	if err != nil {
		s.internal(w, r, "login")
		return
	}
	http.SetCookie(w, auth.SessionCookie(result.Token, result.ExpiresAt))
	writeJSON(w, r, 200, result.Session)
}

func passiveSessionRequest(r *http.Request) bool {
	if r.Method != http.MethodGet || len(r.Header.Values("X-NetHub-Background")) != 1 || r.Header.Get("X-NetHub-Background") != "1" {
		return false
	}
	switch r.URL.Path {
	case prefix + "/devices", prefix + "/users", prefix + "/session", prefix + "/oidc-providers", prefix + "/saml-providers":
		return true
	default:
		return false
	}
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (auth.Session, string, bool) {
	token, err := auth.ReadSessionToken(r)
	if err != nil {
		writeError(w, r, 401, "unauthenticated", "Sign in to continue")
		return auth.Session{}, "", false
	}
	var session auth.Session
	if passiveSessionRequest(r) {
		session, err = s.auth.AuthenticatePassive(r.Context(), token)
	} else {
		session, err = s.auth.Authenticate(r.Context(), token)
	}
	if errors.Is(err, auth.ErrUnauthenticated) {
		http.SetCookie(w, auth.ClearSessionCookie())
		writeError(w, r, 401, "unauthenticated", "Sign in to continue")
		return auth.Session{}, "", false
	}
	if err != nil {
		s.internal(w, r, "session")
		return auth.Session{}, "", false
	}
	return session, token, true
}

func (s *Server) mutation(w http.ResponseWriter, r *http.Request) (auth.Session, string, bool) {
	session, token, ok := s.authenticate(w, r)
	if !ok {
		return auth.Session{}, "", false
	}
	csrf := r.Header.Values("X-CSRF-Token")
	if !s.origin.Check(r, false) || len(csrf) != 1 || !auth.CheckCSRF(session, csrf[0]) {
		writeError(w, r, 403, "csrf_failed", "A valid session CSRF token is required")
		return auth.Session{}, "", false
	}
	return session, token, true
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	token, err := auth.ReadSessionToken(r)
	if err != nil {
		writeJSON(w, r, 200, map[string]bool{"signed_in": false})
		return
	}
	var session auth.Session
	if passiveSessionRequest(r) {
		session, err = s.auth.AuthenticatePassive(r.Context(), token)
	} else {
		session, err = s.auth.Authenticate(r.Context(), token)
	}
	if errors.Is(err, auth.ErrUnauthenticated) {
		http.SetCookie(w, auth.ClearSessionCookie())
		writeJSON(w, r, 200, map[string]bool{"signed_in": false})
		return
	}
	if err != nil {
		s.internal(w, r, "session")
		return
	}
	writeJSON(w, r, 200, struct {
		SignedIn bool `json:"signed_in"`
		auth.Session
	}{true, session})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	_, token, ok := s.mutation(w, r)
	if !ok {
		return
	}
	var input struct{}
	if !readJSON(w, r, &input) {
		return
	}
	if err := s.auth.Logout(r.Context(), token, ip); err != nil {
		s.internal(w, r, "logout")
		return
	}
	http.SetCookie(w, auth.ClearSessionCookie())
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	session, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	values, err := netURLQuery(r)
	if err != nil {
		writeError(w, r, 400, "invalid_request", "Invalid device query")
		return
	}
	query := DeviceQuery{Limit: 50}
	for key, list := range values {
		if len(list) != 1 {
			writeError(w, r, 400, "invalid_request", "Repeated query parameter")
			return
		}
		value := list[0]
		switch key {
		case "limit":
			query.Limit, err = strconv.Atoi(value)
			if err != nil || query.Limit < 1 || query.Limit > 200 {
				writeError(w, r, 400, "invalid_request", "Limit must be between 1 and 200")
				return
			}
		case "cursor":
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
			if err != nil || len(value) > 64 || !uuidPattern.Match(decoded) {
				writeError(w, r, 400, "invalid_request", "Invalid device cursor")
				return
			}
			query.AfterID = string(decoded)
		case "online", "revoked":
			if value != "true" && value != "false" {
				writeError(w, r, 400, "invalid_request", "Filters must be true or false")
				return
			}
			flag := value == "true"
			if key == "online" {
				query.Online = &flag
			} else {
				query.Revoked = &flag
			}
		default:
			writeError(w, r, 400, "invalid_request", "Unknown device query parameter")
			return
		}
	}
	page, err := s.repository.Devices(r.Context(), session.User.ID, query)
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeError(w, r, 401, "unauthenticated", "Sign in to continue")
		return
	}
	if err != nil {
		s.internal(w, r, "devices")
		return
	}
	for i := range page.Items {
		device := &page.Items[i]
		host := device.Subdomain + "." + s.deviceDomain
		if !hostnameLabel.MatchString(device.Subdomain) || len(host) > 253 || host == s.consoleHostname {
			s.internal(w, r, "device URL")
			return
		}
		device.URL = "https://" + host + ":8443"
	}
	if session.User.Role != "admin" {
		page.RelayAlerts = nil
	}
	if len(page.RelayAlerts) > 100 {
		s.internal(w, r, "relay alert projection")
		return
	}
	seenAlerts := make(map[string]bool, len(page.RelayAlerts))
	for _, alert := range page.RelayAlerts {
		if !alert.Valid() || seenAlerts[alert.ID] {
			s.internal(w, r, "relay alert projection")
			return
		}
		seenAlerts[alert.ID] = true
	}
	writeJSON(w, r, 200, page)
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, _, ok := s.mutation(w, r)
	if !ok {
		return
	}
	var input struct{}
	if !readJSON(w, r, &input) {
		return
	}
	if s.rateFailure(w, r, s.enrollLimits.Allow(ip, session.User.ID, time.Now())) {
		return
	}
	result, err := s.repository.IssueEnrollToken(r.Context(), session.User.ID, ip)
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeError(w, r, 401, "unauthenticated", "Sign in to continue")
		return
	}
	if err != nil {
		s.internal(w, r, "enroll token")
		return
	}
	writeJSON(w, r, 201, result)
}

// Query parsing errors must not silently remove filters or pagination bounds.
func netURLQuery(r *http.Request) (map[string][]string, error) {
	if len(r.URL.RawQuery) > 2048 {
		return nil, errors.New("query too long")
	}
	return url.ParseQuery(r.URL.RawQuery)
}
