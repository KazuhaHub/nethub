package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/sso"
)

type samlHTTPBackend struct{ *oidcHTTPBackend }

func (b *samlHTTPBackend) Complete(_ context.Context, _ string, state, response, browser string, _ netip.Addr, _ string) (auth.LoginResult, bool, error) {
	b.completes++
	b.state = state
	b.code = response
	b.browser = browser
	return b.result, b.consumed, b.err
}

func TestSAMLBrowserHTTPBoundary(t *testing.T) {
	s, _, logs := newFixture(t)
	token := func(value byte) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)) }
	browser, state, session := token(1), token(2), token(3)
	backend := &samlHTTPBackend{&oidcHTTPBackend{start: sso.StartResult{BrowserToken: browser, RedirectURL: "https://idp.example.com/login", ExpiresAt: time.Now().Add(sso.FlowLifetime)}, result: auth.LoginResult{Token: session, Session: auth.Session{ExpiresAt: time.Now().Add(time.Hour)}}, consumed: true}}
	s.saml = backend
	start := prefix + "/saml/company/start"
	callback := prefix + "/saml/company/callback"
	if got := call(s, "POST", start, "{}", nil, map[string]string{"Content-Type": "application/json"}); got.Code != 403 || backend.starts != 0 {
		t.Fatal("start missing Origin", got.Code)
	}
	got := call(s, "POST", start, "{}", nil, map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.com"})
	cookies := got.Result().Cookies()
	if got.Code != 200 || len(cookies) != 1 || cookies[0].Name != samlCookieName || cookies[0].SameSite != http.SameSiteNoneMode || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].Domain != "" {
		t.Fatal("cross-site SAML cookie policy", got.Code)
	}
	cookie := cookies[0]
	body := url.Values{"SAMLResponse": {"private-signed-response"}, "RelayState": {state}}.Encode()
	for _, test := range []struct {
		body, query, media string
		cookie             *http.Cookie
	}{
		{body: body + "&RelayState=" + state, media: "application/x-www-form-urlencoded", cookie: cookie},
		{body: body + "&unknown=true", media: "application/x-www-form-urlencoded", cookie: cookie},
		{body: body, query: "?RelayState=" + state, media: "application/x-www-form-urlencoded", cookie: cookie},
		{body: body, media: "application/json", cookie: cookie},
		{body: body, media: "application/x-www-form-urlencoded"},
		{body: strings.Repeat("x", 2<<20+1), media: "application/x-www-form-urlencoded", cookie: cookie},
	} {
		s.ssoCallbackLimits = auth.NewAttemptLimiter()
		got := call(s, "POST", callback+test.query, test.body, test.cookie, map[string]string{"Content-Type": test.media})
		if got.Code != 303 || got.Header().Get("Location") != "/login?error=sso_failed" || backend.completes != 0 || len(got.Result().Cookies()) != 0 {
			t.Fatal("malformed SAML callback reached service", got.Code)
		}
	}
	s.ssoCallbackLimits = auth.NewAttemptLimiter()
	got = call(s, "POST", callback, body, cookie, map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://idp.example.com"})
	if got.Code != 303 || got.Header().Get("Location") != "/" || backend.completes != 1 || backend.state != state || backend.browser != browser || backend.code != "private-signed-response" {
		t.Fatal("IdP POST not accepted by HTTP boundary", got.Code)
	}
	var sessionCookie, cleared bool
	for _, value := range got.Result().Cookies() {
		if value.Name == auth.SessionCookieName {
			sessionCookie = value.SameSite == http.SameSiteLaxMode && value.Secure && value.HttpOnly
		}
		if value.Name == samlCookieName {
			cleared = value.MaxAge < 0 && value.SameSite == http.SameSiteNoneMode
		}
	}
	if !sessionCookie || !cleared {
		t.Fatal("SAML callback changed session-cookie policy or retained consumed binding")
	}
	backend.consumed = false
	backend.err = sso.ErrFlow
	s.ssoCallbackLimits = auth.NewAttemptLimiter()
	got = call(s, "POST", callback, body, cookie, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if got.Code != 303 || len(got.Result().Cookies()) != 0 {
		t.Fatal("stale callback cleared a newer SAML binding")
	}
	if strings.Contains(logs.String(), browser) || strings.Contains(logs.String(), state) || strings.Contains(logs.String(), "private-signed-response") {
		t.Fatal("SAML values entered HTTP logs")
	}
}
