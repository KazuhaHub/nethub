package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

type fixtureRepository struct {
	mu       sync.Mutex
	hash     string
	sessions map[string]auth.SessionRecord
	lastIP   netip.Addr
	issued   int
	failure  error
	page     DevicePage
}

func (f *fixtureRepository) PasswordCandidate(context.Context, string) (auth.Candidate, error) {
	return auth.Candidate{User: auth.User{ID: "fixture", Email: "member@example.com", Role: "member"}, PasswordHash: f.hash}, f.failure
}
func (f *fixtureRepository) CreateSession(_ context.Context, candidate auth.Candidate, record auth.SessionRecord) (auth.SessionRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record.User = candidate.User
	f.lastIP = record.IP
	f.sessions[string(record.TokenHash)] = record
	return record, f.failure
}
func (f *fixtureRepository) LookupSession(_ context.Context, digest []byte, _ time.Duration) (auth.SessionRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return auth.SessionRecord{}, f.failure
	}
	record, ok := f.sessions[string(digest)]
	if !ok {
		return auth.SessionRecord{}, auth.ErrUnauthenticated
	}
	return record, nil
}
func (f *fixtureRepository) DeleteSession(_ context.Context, digest []byte, _ netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, string(digest))
	return f.failure
}
func (f *fixtureRepository) LookupSessionPassive(ctx context.Context, digest []byte, idle time.Duration) (auth.SessionRecord, error) {
	return f.LookupSession(ctx, digest, idle)
}

type passiveOnlyRepository struct {
	*fixtureRepository
	passiveCalls int
}

func (f *passiveOnlyRepository) LookupSession(context.Context, []byte, time.Duration) (auth.SessionRecord, error) {
	return auth.SessionRecord{}, auth.ErrUnavailable
}

func (f *passiveOnlyRepository) LookupSessionPassive(ctx context.Context, digest []byte, idle time.Duration) (auth.SessionRecord, error) {
	f.passiveCalls++
	return f.fixtureRepository.LookupSession(ctx, digest, idle)
}

func TestOnlyBackgroundInventoryUsesPassiveAuthentication(t *testing.T) {
	server, original, _ := newFixture(t)
	repository := &passiveOnlyRepository{fixtureRepository: original}
	service, err := auth.NewService(repository, auth.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server.auth = service
	cookie, session := fixtureLogin(t, server)
	headers := map[string]string{"X-NetHub-Background": "1"}
	if response := call(server, "GET", prefix+"/devices", "", cookie, headers); response.Code != 200 || repository.passiveCalls != 1 {
		t.Fatal("background inventory did not use passive session validation")
	}
	if response := call(server, "GET", prefix+"/devices", "", cookie, nil); response.Code != 500 {
		t.Fatal("manual inventory unexpectedly bypassed active authentication")
	}
	headers["Content-Type"] = "application/json"
	headers["X-CSRF-Token"] = session.CSRFToken
	if response := call(server, "POST", prefix+"/enroll-tokens", `{}`, cookie, headers); response.Code != 500 || repository.passiveCalls != 1 {
		t.Fatal("background marker changed mutation authentication")
	}
}
func (f *fixtureRepository) Health(context.Context) error { return f.failure }
func (f *fixtureRepository) Devices(context.Context, string, DeviceQuery) (DevicePage, error) {
	return f.page, f.failure
}
func (f *fixtureRepository) IssueEnrollToken(_ context.Context, _ string, ip netip.Addr) (EnrollToken, error) {
	f.issued++
	f.lastIP = ip
	return EnrollToken{Token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), ExpiresAt: time.Now().Add(15 * time.Minute)}, f.failure
}
func (f *fixtureRepository) LoginFailed(_ context.Context, ip netip.Addr) error {
	f.lastIP = ip
	return f.failure
}

func newFixture(t *testing.T) (*Server, *fixtureRepository, *bytes.Buffer) {
	t.Helper()
	hash, err := auth.HashPassword("a fixture passphrase")
	if err != nil {
		t.Fatal(err)
	}
	repository := &fixtureRepository{hash: hash, sessions: map[string]auth.SessionRecord{}, page: DevicePage{Items: []Device{}}}
	service, err := auth.NewService(repository, auth.Config{})
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	server, err := New(Config{Origin: "https://console.example.com", DeviceDomain: "router.example.com", Logger: slog.New(slog.NewJSONHandler(logs, nil))}, service, repository)
	if err != nil {
		t.Fatal(err)
	}
	return server, repository, logs
}

func call(server *Server, method, path, body string, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://console.example.com"+path, strings.NewReader(body))
	request.RemoteAddr = "192.0.2.100:1234"
	if cookie != nil {
		request.AddCookie(cookie)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func fixtureLogin(t *testing.T, server *Server) (*http.Cookie, auth.Session) {
	t.Helper()
	response := call(server, "POST", prefix+"/login", `{"email":"member@example.com","password":"a fixture passphrase"}`, nil, map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.com"})
	if response.Code != 200 {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing session cookie")
	}
	var session auth.Session
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	return cookies[0], session
}

func TestHTTPAuthenticationCSRFAndSecretBoundaries(t *testing.T) {
	server, repository, logs := newFixture(t)
	cookie, session := fixtureLogin(t, server)
	response := call(server, "GET", prefix+"/session", "", cookie, nil)
	if response.Code != 200 || !strings.Contains(response.Body.String(), session.CSRFToken) || strings.Contains(response.Body.String(), cookie.Value) {
		t.Fatal("session response exposed bearer or lost CSRF token")
	}
	for _, headers := range []map[string]string{
		{"Content-Type": "application/json"},
		{"Content-Type": "application/json", "X-CSRF-Token": "wrong"},
		{"Content-Type": "application/json", "X-CSRF-Token": session.CSRFToken, "Origin": "https://device.router.example.com"},
	} {
		if got := call(server, "POST", prefix+"/enroll-tokens", `{}`, cookie, headers); got.Code != 403 {
			t.Fatalf("invalid CSRF status=%d", got.Code)
		}
	}
	if repository.issued != 0 {
		t.Fatal("rejected mutation reached token issuance")
	}
	headers := map[string]string{"Content-Type": "application/json", "X-CSRF-Token": session.CSRFToken}
	response = call(server, "POST", prefix+"/enroll-tokens", `{}`, cookie, headers)
	if response.Code != 201 || repository.issued != 1 {
		t.Fatalf("enroll status=%d", response.Code)
	}
	for i := 0; i < 4; i++ {
		if response = call(server, "POST", prefix+"/enroll-tokens", `{}`, cookie, headers); response.Code != 201 {
			t.Fatal("unexpected token budget")
		}
	}
	response = call(server, "POST", prefix+"/enroll-tokens", `{}`, cookie, headers)
	if response.Code != 429 || response.Header().Get("Retry-After") == "" {
		t.Fatal("token issuance rate limit missing")
	}
	response = call(server, "POST", prefix+"/logout", `{}`, cookie, headers)
	if response.Code != 204 || response.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout did not clear cookie")
	}
	if response = call(server, "GET", prefix+"/devices", "", cookie, nil); response.Code != 401 {
		t.Fatal("logged-out bearer accepted")
	}
	if response = call(server, "GET", prefix+"/session", "", cookie, nil); response.Code != 200 || !strings.Contains(response.Body.String(), `"signed_in":false`) {
		t.Fatal("logged-out session query incorrect")
	}
	if strings.Contains(logs.String(), cookie.Value) || strings.Contains(logs.String(), session.CSRFToken) || strings.Contains(logs.String(), repository.hash) {
		t.Fatal("authentication material leaked to logs")
	}
}

func TestHTTPStrictJSONOriginsAndHeaders(t *testing.T) {
	server, _, _ := newFixture(t)
	for name, test := range map[string]struct {
		body, contentType, origin string
		status                    int
	}{
		"missing origin":  {`{}`, "application/json", "", 403},
		"foreign origin":  {`{}`, "application/json", "https://evil.example.com", 403},
		"form":            {`email=member`, "application/x-www-form-urlencoded", "https://console.example.com", 415},
		"unknown field":   {`{"email":"member@example.com","password":"fixture","role":"admin"}`, "application/json", "https://console.example.com", 400},
		"duplicate field": {`{"email":"first@example.com","email":"second@example.com","password":"fixture"}`, "application/json", "https://console.example.com", 400},
		"case alias":      {`{"email":"first@example.com","Email":"second@example.com","password":"fixture"}`, "application/json", "https://console.example.com", 400},
		"null":            {`null`, "application/json", "https://console.example.com", 400},
		"trailing":        {`{} {}`, "application/json", "https://console.example.com", 400},
		"invalid UTF8":    {"{\"email\":\"\xff\"}", "application/json", "https://console.example.com", 400},
		"oversize":        {strings.Repeat(" ", maxBody+1), "application/json", "https://console.example.com", 413},
	} {
		t.Run(name, func(t *testing.T) {
			headers := map[string]string{"Content-Type": test.contentType}
			if test.origin != "" {
				headers["Origin"] = test.origin
			}
			response := call(server, "POST", prefix+"/login", test.body, nil, headers)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			csp := response.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-") || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Cross-Origin-Opener-Policy") != "same-origin" || strings.Contains(response.Header().Get("Strict-Transport-Security"), "includeSubDomains") {
				t.Fatal("incomplete security headers")
			}
		})
	}
	if response := call(server, "OPTIONS", prefix+"/login", "", nil, nil); response.Code != 405 || response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unexpected CORS or method handling")
	}
	if response := call(server, "GET", prefix+"/session", `{}`, nil, nil); response.Code != 400 {
		t.Fatal("GET body accepted")
	}
	if response := call(server, "HEAD", "/healthz", "", nil, nil); response.Code != 200 || response.Body.Len() != 0 {
		t.Fatal("HEAD health request returned a body")
	}
	request := httptest.NewRequest("GET", "https://wrong.example.com"+prefix+"/session", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != 400 {
		t.Fatal("foreign Host accepted")
	}
}

func TestHTTPDeviceQueryProxyAndFailureHandling(t *testing.T) {
	server, repository, logs := newFixture(t)
	cookie, _ := fixtureLogin(t, server)
	for _, query := range []string{"?limit=0", "?limit=201", "?limit=1&limit=2", "?cursor=not-a-cursor", "?online=yes", "?tenant=other", "?revoked=true;limit=1"} {
		if response := call(server, "GET", prefix+"/devices"+query, "", cookie, nil); response.Code != 400 {
			t.Fatalf("invalid query accepted: %s", query)
		}
	}
	response := call(server, "GET", prefix+"/session", "", cookie, map[string]string{"X-Forwarded-For": "192.0.2.200"})
	if response.Code != 200 || !strings.Contains(logs.String(), "untrusted peer") {
		t.Fatal("untrusted proxy headers not reported")
	}
	repository.page.Items = []Device{{ID: "fixture", Subdomain: "branch", Owner: Owner{ID: "fixture"}}}
	response = call(server, "GET", prefix+"/devices", "", cookie, nil)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "https://branch.router.example.com:8443") {
		t.Fatal("device URL not derived from deployment configuration")
	}
	server.deviceDomain = "example.com"
	repository.page.Items[0].Subdomain = "console"
	response = call(server, "GET", prefix+"/devices", "", cookie, nil)
	if response.Code != 500 || strings.Contains(response.Body.String(), "https://console") {
		t.Fatal("device received the console hostname")
	}
	repository.failure = errors.New("private diagnostic includes a secret")
	response = call(server, "GET", prefix+"/session", "", cookie, nil)
	if response.Code != 500 || strings.Contains(response.Body.String(), "private diagnostic") || strings.Contains(logs.String(), "private diagnostic") {
		t.Fatal("raw backend error leaked")
	}
}
