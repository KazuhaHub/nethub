package web

import (
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/sso"
)

const samlCookieName = "__Host-nethub_saml"

func samlFlowCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{Name: samlCookieName, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode, Expires: expires.UTC()}
}
func clearSAMLFlowCookie() *http.Cookie {
	cookie := samlFlowCookie("", time.Unix(1, 0))
	cookie.MaxAge = -1
	return cookie
}

func (s *Server) samlLoginProviders(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, r, 400, "invalid_request", "Provider requests do not accept query parameters")
		return
	}
	providers := []sso.Choice{}
	if s.saml != nil {
		var err error
		providers, err = s.saml.Providers(r.Context())
		if err != nil {
			s.internal(w, r, "SAML providers")
			return
		}
	}
	writeJSON(w, r, 200, map[string]any{"items": providers})
}

func (s *Server) samlBrowser(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix+"/saml/"), "/")
	if len(parts) != 2 || !providerSlug.MatchString(parts[0]) {
		writeError(w, r, 404, "not_found", "Not found")
		return
	}
	switch parts[1] {
	case "metadata":
		s.samlMetadata(w, r)
	case "start":
		if allowMethod(w, r, "POST") {
			s.startSSO(w, r, ip, parts[0], s.saml, samlFlowCookie)
		}
	case "callback":
		if allowMethod(w, r, "POST") {
			s.completeSAML(w, r, ip, parts[0])
		}
	default:
		writeError(w, r, 404, "not_found", "Not found")
	}
}

func (s *Server) completeSAML(w http.ResponseWriter, r *http.Request, ip netip.Addr, slug string) {
	reason := "callback"
	fail := func() {
		if s.saml != nil {
			if err := s.saml.Failed(r.Context(), ip.Unmap(), reason); err != nil {
				s.logger.Error("Console operation failed", "operation", "SSO failure audit")
			}
		}
		http.Redirect(w, r, "/login?error=sso_failed", http.StatusSeeOther)
	}
	if s.ssoCallbackLimits.Allow(ip, ip.String()+":"+slug, time.Now()) != nil {
		http.Redirect(w, r, "/login?error=sso_failed", http.StatusSeeOther)
		return
	}
	if s.saml == nil || r.URL.RawQuery != "" || r.Header.Get("Content-Encoding") != "" {
		fail()
		return
	}
	media, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8") {
		fail()
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		fail()
		return
	}
	values, err := url.ParseQuery(string(body))
	if err != nil || len(values) != 2 {
		fail()
		return
	}
	for name, list := range values {
		if len(list) != 1 || name != "SAMLResponse" && name != "RelayState" {
			fail()
			return
		}
	}
	if _, err = sso.Digest(values.Get("RelayState")); err != nil {
		fail()
		return
	}
	cookies := r.CookiesNamed(samlCookieName)
	if len(cookies) != 1 {
		fail()
		return
	}
	if _, err = sso.Digest(cookies[0].Value); err != nil {
		fail()
		return
	}
	// The IdP POST is cross-site. Its authorization is the one-use browser-bound
	// request plus authcore signature/destination/request validation, not Origin.
	result, consumed, err := s.saml.Complete(r.Context(), slug, values.Get("RelayState"), values.Get("SAMLResponse"), cookies[0].Value, ip.Unmap(), r.UserAgent())
	if consumed {
		http.SetCookie(w, clearSAMLFlowCookie())
	}
	if err != nil {
		reason = sso.FailureReason(err)
		fail()
		return
	}
	http.SetCookie(w, auth.SessionCookie(result.Token, result.ExpiresAt))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
