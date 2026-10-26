package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/sso"
)

type oidcHTTPBackend struct {
	starts, completes, failures      int
	start                            sso.StartResult
	result                           auth.LoginResult
	err                              error
	consumed                         bool
	code, state, browser, invitation string
	reason                           string
}

func (*oidcHTTPBackend) Providers(context.Context) ([]sso.Choice, error) {
	return []sso.Choice{{Slug: "company", DisplayName: "Company"}}, nil
}
func (b *oidcHTTPBackend) Start(_ context.Context, _ string, invite string) (sso.StartResult, error) {
	b.starts++
	b.invitation = invite
	return b.start, b.err
}
func (b *oidcHTTPBackend) Complete(_ context.Context, _ string, state, code, _ string, browser string, _ netip.Addr, _ string) (auth.LoginResult, bool, error) {
	b.completes++
	b.code = code
	b.state = state
	b.browser = browser
	return b.result, b.consumed, b.err
}
func (b *oidcHTTPBackend) Failed(_ context.Context, _ netip.Addr, reason string) error {
	b.failures++
	b.reason = reason
	return nil
}

func TestOIDCBrowserHTTPBoundary(t *testing.T) {
	s, _, logs := newFixture(t)
	token := func(value byte) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)) }
	browser, state, sessionToken, invite := token(1), token(2), token(3), token(4)
	backend := &oidcHTTPBackend{start: sso.StartResult{BrowserToken: browser, RedirectURL: "https://idp.example/authorize?state=" + state, ExpiresAt: time.Now().Add(sso.FlowLifetime)}, result: auth.LoginResult{Token: sessionToken, Session: auth.Session{User: auth.User{ID: "bound", Email: "bound@example.com", Role: "member"}, ExpiresAt: time.Now().Add(time.Hour)}}, consumed: true}
	s.sso = backend
	headers := map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.com"}
	start := prefix + "/oidc/company/start"
	callback := prefix + "/oidc/company/callback"
	if got := call(s, "GET", prefix+"/oidc/providers", "", nil, nil); got.Code != 200 || strings.Contains(got.Body.String(), "client_secret") || !strings.Contains(got.Body.String(), "Company") {
		t.Fatal("login catalog", got.Code)
	}
	if got := call(s, "POST", start, "{}", nil, map[string]string{"Content-Type": "application/json"}); got.Code != 403 || backend.starts != 0 {
		t.Fatal("missing Origin reached SSO", got.Code)
	}
	if got := call(s, "POST", start, "{}", nil, map[string]string{"Content-Type": "application/json", "Origin": "https://other.example"}); got.Code != 403 || backend.starts != 0 {
		t.Fatal("foreign Origin reached SSO", got.Code)
	}
	for _, body := range []string{`{"unexpected":true}`, `{"invite_token":"invalid"}`, `{"invite_token":"a","invite_token":"b"}`, `{"invite_token":null}`, `{"invite_token":""}`, `{"invite_token":true}`} {
		if got := call(s, "POST", start, body, nil, headers); got.Code != 400 || backend.starts != 0 {
			t.Fatal("malformed SSO start", got.Code)
		}
	}
	got := call(s, "POST", start, `{"invite_token":"`+invite+`"}`, nil, headers)
	var reply map[string]string
	if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &reply) != nil || reply["redirect_url"] != backend.start.RedirectURL || backend.invitation != invite || strings.Contains(got.Body.String(), browser) || strings.Contains(got.Body.String(), invite) {
		t.Fatal("SSO start response", got.Code)
	}
	cookies := got.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != oidcCookieName || cookies[0].Value != browser || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].Path != "/" || cookies[0].Domain != "" || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("browser binding cookie policy")
	}
	flowCookie := cookies[0]
	for _, method := range []string{"POST", "HEAD", "DELETE"} {
		if got := call(s, method, callback+"?state="+state+"&code=private-code", "", flowCookie, nil); got.Code != 405 || backend.completes != 0 {
			t.Fatal("non-GET callback reached exchange", method, got.Code)
		}
	}
	for _, query := range []string{"?state=invalid&code=private-code", "?state=" + state + "&state=" + state + "&code=private-code", "?state=" + state + "&code=a&code=b", "?state=" + state + "&code=a&return_to=https://other.example", "?state=" + state + "&code=a&iss=", "?state=%zz"} {
		s.ssoCallbackLimits = auth.NewAttemptLimiter()
		if got := call(s, "GET", callback+query, "", flowCookie, nil); got.Code != 303 || got.Header().Get("Location") != "/login?error=sso_failed" || backend.completes != 0 {
			t.Fatal("malformed callback reached protocol", got.Code)
		}
	}
	s.ssoCallbackLimits = auth.NewAttemptLimiter()
	request := httptest.NewRequest("GET", "https://console.example.com"+callback+"?state="+state+"&code=private-code", nil)
	request.RemoteAddr = "192.0.2.100:1234"
	request.AddCookie(flowCookie)
	request.AddCookie(flowCookie)
	duplicate := httptest.NewRecorder()
	s.ServeHTTP(duplicate, request)
	if duplicate.Code != 303 || backend.completes != 0 {
		t.Fatal("duplicate browser cookies accepted")
	}
	s.ssoCallbackLimits = auth.NewAttemptLimiter()
	got = call(s, "GET", callback+"?state="+state+"&code=private-code", "", flowCookie, nil)
	if got.Code != 303 || got.Header().Get("Location") != "/" || backend.code != "private-code" || backend.browser != browser || backend.state != state {
		t.Fatal("callback dispatch", got.Code)
	}
	var cleared, sessionSet bool
	for _, cookie := range got.Result().Cookies() {
		if cookie.Name == oidcCookieName && cookie.MaxAge < 0 {
			cleared = true
		}
		if cookie.Name == auth.SessionCookieName && cookie.Value == sessionToken && cookie.HttpOnly && cookie.Secure {
			sessionSet = true
		}
	}
	if !cleared || !sessionSet {
		t.Fatal("successful callback lost binding cleanup or session")
	}
	backend.err = errors.New("private upstream credential detail")
	backend.consumed = false
	s.ssoCallbackLimits = auth.NewAttemptLimiter()
	got = call(s, "GET", callback+"?state="+state+"&code=private-code", "", flowCookie, nil)
	if got.Code != 303 || len(got.Result().Cookies()) != 0 || got.Header().Get("Location") != "/login?error=sso_failed" {
		t.Fatal("stale callback cleared a newer browser binding")
	}
	if backend.reason != "unavailable" {
		t.Fatal("failure audit lost its bounded category")
	}
	backend.consumed = true
	s.ssoCallbackLimits = auth.NewAttemptLimiter()
	got = call(s, "GET", callback+"?state="+state+"&error=access_denied&error_description=private-upstream-error", "", flowCookie, nil)
	if got.Code != 303 || backend.code != "" || len(got.Result().Cookies()) != 1 || got.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatal("provider refusal lost one-use cleanup")
	}
	for _, secret := range []string{browser, state, invite, sessionToken, "private-code", "private-upstream-error", "private upstream credential detail"} {
		if strings.Contains(got.Body.String(), secret) || strings.Contains(got.Header().Get("Location"), secret) || strings.Contains(logs.String(), secret) {
			t.Fatal("callback diagnostics leaked protocol material")
		}
	}
	// Failed callback traffic has a bounded audit budget even without a cookie.
	s.ssoCallbackLimits = auth.NewAttemptLimiter()
	before := backend.failures
	for range 20 {
		call(s, "GET", callback+"?state=invalid", "", nil, nil)
	}
	if backend.failures-before != 5 {
		t.Fatal("unbounded failed callback audits", backend.failures-before)
	}
	backend.err = nil
	cookie, _ := fixtureLogin(t, s)
	beforeStarts := backend.starts
	if got := call(s, "POST", start, "{}", cookie, headers); got.Code != 409 || backend.starts != beforeStarts {
		t.Fatal("SSO silently replaced signed-in account", got.Code)
	}
}
