package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/sso"
)

const oidcCookieName = "__Host-nethub_oidc"

func flowCookie(token string, expires time.Time) *http.Cookie {
	return &http.Cookie{Name: oidcCookieName, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires.UTC()}
}

func clearFlowCookie() *http.Cookie { c := flowCookie("", time.Unix(1, 0)); c.MaxAge = -1; return c }

func (s *Server) loginProviders(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, r, 400, "invalid_request", "Provider requests do not accept query parameters")
		return
	}
	if s.sso == nil {
		writeJSON(w, r, 200, map[string]any{"items": []sso.Choice{}})
		return
	}
	providers, err := s.sso.Providers(r.Context())
	if err != nil {
		s.internal(w, r, "SSO providers")
		return
	}
	writeJSON(w, r, 200, map[string]any{"items": providers})
}

func (s *Server) oidcBrowser(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix+"/oidc/"), "/")
	if len(parts) != 2 || !providerSlug.MatchString(parts[0]) || parts[1] != "start" && parts[1] != "callback" {
		writeError(w, r, 404, "not_found", "Not found")
		return
	}
	if parts[1] == "start" {
		if allowMethod(w, r, "POST") {
			s.startOIDC(w, r, ip, parts[0])
		}
		return
	}
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		writeError(w, r, 405, "method_not_allowed", "Method not allowed")
		return
	}
	s.completeOIDC(w, r, ip, parts[0])
}

func (s *Server) startOIDC(w http.ResponseWriter, r *http.Request, ip netip.Addr, slug string) {
	if !s.origin.Check(r, true) {
		writeError(w, r, 403, "csrf_failed", "A matching console Origin is required")
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, r, 400, "invalid_request", "SSO start does not accept query parameters")
		return
	}
	// Changing the signed-in account is explicit. A failed or unavailable session
	// lookup must not silently establish a different identity in this browser.
	if cookies := r.CookiesNamed(auth.SessionCookieName); len(cookies) > 0 {
		token, err := auth.ReadSessionToken(r)
		if err != nil {
			writeError(w, r, 409, "already_signed_in", "Sign out before starting SSO")
			return
		}
		_, err = s.auth.AuthenticatePassive(r.Context(), token)
		if err == nil {
			writeError(w, r, 409, "already_signed_in", "Sign out before starting SSO")
			return
		}
		if !errors.Is(err, auth.ErrUnauthenticated) {
			s.internal(w, r, "SSO session")
			return
		}
		http.SetCookie(w, auth.ClearSessionCookie())
	}
	var input struct {
		InviteToken json.RawMessage `json:"invite_token"`
	}
	if !readJSON(w, r, &input, "invite_token") {
		return
	}
	var invite string
	if input.InviteToken != nil {
		if bytes.Equal(bytes.TrimSpace(input.InviteToken), []byte("null")) || json.Unmarshal(input.InviteToken, &invite) != nil {
			writeError(w, r, 400, "invalid_request", "Invalid invitation token")
			return
		}
		if _, err := auth.InvitationDigest(invite); err != nil {
			writeError(w, r, 400, "invalid_request", "Invalid invitation token")
			return
		}
	}
	if s.rateFailure(w, r, s.ssoStartLimits.Allow(ip, ip.String()+":"+slug, time.Now())) {
		return
	}
	if s.sso == nil {
		writeError(w, r, 503, "sso_unavailable", "SSO sign-in unavailable")
		return
	}
	result, err := s.sso.Start(r.Context(), slug, invite)
	if err != nil {
		if auditErr := s.sso.Failed(r.Context(), ip.Unmap(), sso.FailureReason(err)); auditErr != nil {
			s.internal(w, r, "SSO failure audit")
			return
		}
		writeError(w, r, 401, "sso_failed", "SSO sign-in failed")
		return
	}
	http.SetCookie(w, flowCookie(result.BrowserToken, result.ExpiresAt))
	writeJSON(w, r, 200, map[string]string{"redirect_url": result.RedirectURL})
}

func (s *Server) completeOIDC(w http.ResponseWriter, r *http.Request, ip netip.Addr, slug string) {
	if s.ssoCallbackLimits.Allow(ip, ip.String()+":"+slug, time.Now()) != nil {
		http.Redirect(w, r, "/login?error=sso_failed", http.StatusSeeOther)
		return
	}
	reason := "callback"
	fail := func() {
		if s.sso != nil {
			if err := s.sso.Failed(r.Context(), ip.Unmap(), reason); err != nil {
				s.logger.Error("Console operation failed", "operation", "SSO failure audit")
			}
		}
		http.Redirect(w, r, "/login?error=sso_failed", http.StatusSeeOther)
	}
	if s.sso == nil || len(r.URL.RawQuery) > 20<<10 {
		fail()
		return
	}
	parsed, err := netURLQuery(r)
	values := url.Values(parsed)
	if err != nil {
		fail()
		return
	}
	for key, list := range values {
		if len(list) != 1 || key != "state" && key != "code" && key != "error" && key != "error_description" && key != "error_uri" && key != "session_state" && key != "iss" {
			fail()
			return
		}
	}
	if values.Has("iss") && values.Get("iss") == "" {
		fail()
		return
	}
	cookies := r.CookiesNamed(oidcCookieName)
	if len(cookies) != 1 {
		fail()
		return
	}
	if _, err = sso.Digest(values.Get("state")); err != nil {
		fail()
		return
	}
	if _, err = sso.Digest(cookies[0].Value); err != nil {
		fail()
		return
	}
	code := values.Get("code")
	if values.Has("error") {
		code = ""
	}
	result, consumed, err := s.sso.Complete(r.Context(), slug, values.Get("state"), code, values.Get("iss"), cookies[0].Value, ip.Unmap(), r.UserAgent())
	if consumed {
		http.SetCookie(w, clearFlowCookie())
	}
	if err != nil {
		reason = sso.FailureReason(err)
		fail()
		return
	}
	http.SetCookie(w, auth.SessionCookie(result.Token, result.ExpiresAt))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
