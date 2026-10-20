package device

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

func testHTTP(t *testing.T, service *Service, log io.Writer, proxies ...netip.Prefix) *HTTPServer {
	t.Helper()
	handler, err := NewHTTP(HTTPConfig{Origin: "https://console.example.com", TrustedProxies: proxies,
		Logger: slog.New(slog.NewJSONHandler(log, nil))}, service)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func requestHTTP(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://console.example.com"+enrollPath, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:12345"
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestHTTPRejectsBeforeEnrollment(t *testing.T) {
	input := fixtureRequest(t)
	valid, _ := json.Marshal(input)
	for _, test := range []struct {
		name   string
		status int
		mutate func(*http.Request)
	}{
		{"host", 400, func(r *http.Request) { r.Host = "attacker.example.com" }},
		{"path", 404, func(r *http.Request) { r.URL.Path += "/" }},
		{"encoded_path", 404, func(r *http.Request) { r.URL.RawPath = "/api/v1/devices/%65nroll" }},
		{"method", 405, func(r *http.Request) { r.Method = "GET" }},
		{"head", 405, func(r *http.Request) { r.Method = "HEAD" }},
		{"preflight", 405, func(r *http.Request) { r.Method = "OPTIONS" }},
		{"origin", 403, func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example.com") }},
		{"null_origin", 403, func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{"repeated_origin", 403, func(r *http.Request) {
			r.Header["Origin"] = []string{"https://console.example.com", "https://console.example.com"}
		}},
		{"query_token", 400, func(r *http.Request) { r.URL.RawQuery = "enroll_token=" + input.EnrollToken }},
		{"empty_query", 400, func(r *http.Request) { r.URL.ForceQuery = true }},
		{"peer", 400, func(r *http.Request) { r.RemoteAddr = "invalid" }},
		{"media", 415, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
		{"charset", 415, func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=latin1") }},
		{"repeated_media", 415, func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }},
		{"compressed", 415, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"empty_encoding", 415, func(r *http.Request) { r.Header["Content-Encoding"] = []string{""} }},
		{"too_large", 413, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", protocol.MaxBodyBytes+1)))
		}},
		{"duplicate", 400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"platform":"opnsense","platform":"openwrt"}`))
		}},
		{"version", 400, func(r *http.Request) {
			incompatible := input
			incompatible.AgentProtocolVersion = "2.0.0"
			data, err := json.Marshal(incompatible)
			if err != nil {
				t.Fatal(err)
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{}
			var logs bytes.Buffer
			handler := testHTTP(t, fixtureService(t, repository), &logs)
			r := requestHTTP(string(valid))
			test.mutate(r)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.status || repository.calls.Load() != 0 {
				t.Fatalf("status=%d, repository calls=%d", w.Code, repository.calls.Load())
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Access-Control-Allow-Origin") != "" ||
				strings.Contains(w.Body.String()+logs.String(), input.EnrollToken) {
				t.Fatal("rejection exposes credentials or permits caching/CORS")
			}
			if r.Method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD response has a body")
			}
			if test.name == "version" && !strings.Contains(w.Body.String(), "incompatible_protocol") {
				t.Fatal("incompatible major has no readable error")
			}
		})
	}
}

func TestHTTPClientAddressAndSafeFailures(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		repository := &fakeRepository{}
		service := fixtureService(t, repository)
		var logs bytes.Buffer
		var proxies []netip.Prefix
		if trusted {
			proxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
		}
		handler := testHTTP(t, service, &logs, proxies...)
		input := fixtureRequest(t)
		data, _ := json.Marshal(input)
		r := requestHTTP(string(data))
		r.Header.Set("Origin", "https://console.example.com")
		r.Header.Set("Cookie", "nethub_session=irrelevant-secret")
		r.Header.Set("X-Forwarded-For", "2001:db8::1")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		expected := netip.MustParseAddr("192.0.2.1")
		if trusted {
			expected = netip.MustParseAddr("2001:db8::1")
		}
		if w.Code != 201 || repository.record.SourceIP != expected || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("enrollment did not use the trusted-hop address or issued a browser session")
		}
		if strings.Contains(logs.String(), input.EnrollToken) || strings.Contains(logs.String(), "irrelevant-secret") ||
			strings.Contains(logs.String(), "2001:db8::1") {
			t.Fatal("request values leaked to logs")
		}
	}
	for _, failure := range []error{ErrDenied, errors.New("private dependency detail")} {
		repository := &fakeRepository{failure: failure}
		var logs bytes.Buffer
		handler := testHTTP(t, fixtureService(t, repository), &logs)
		data, _ := json.Marshal(fixtureRequest(t))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, requestHTTP(string(data)))
		want := 503
		if errors.Is(failure, ErrDenied) {
			want = 401
		}
		if w.Code != want || strings.Contains(w.Body.String()+logs.String(), "private dependency detail") ||
			strings.Contains(w.Body.String(), "device_secret") {
			t.Fatal("failed enrollment exposes dependency diagnostics or partial credentials")
		}
	}
}

func TestHTTPRateLimitCannotBeBypassedByForwarding(t *testing.T) {
	repository := &fakeRepository{failure: ErrDenied}
	service := fixtureService(t, repository)
	// Admission, not Argon2 performance, is under test.
	service.hash = func(string) (string, error) { return "$argon2id$" + strings.Repeat("x", 64), nil }
	handler := testHTTP(t, service, io.Discard)
	data, _ := json.Marshal(fixtureRequest(t))
	for i := 0; i < 11; i++ {
		r := requestHTTP(string(data))
		r.Header.Set("X-Forwarded-For", netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(i)}).String())
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if i < 10 && w.Code != 401 || i == 10 && (w.Code != 429 || w.Header().Get("Retry-After") != "60") {
			t.Fatalf("attempt %d: status=%d", i, w.Code)
		}
	}
	if repository.calls.Load() != 10 {
		t.Fatal("untrusted forwarding headers changed the admission budget")
	}
}

func TestHTTPBusyAndInvalidTrustedChain(t *testing.T) {
	repository := &fakeRepository{}
	service := fixtureService(t, repository)
	handler := testHTTP(t, service, io.Discard, netip.MustParsePrefix("192.0.2.0/24"))
	data, _ := json.Marshal(fixtureRequest(t))
	service.workers <- struct{}{}
	service.workers <- struct{}{}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, requestHTTP(string(data)))
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" || repository.calls.Load() != 0 {
		t.Fatal("worker saturation did not reject admission before storage")
	}
	r := requestHTTP(string(data))
	r.Header.Set("X-Forwarded-For", "invalid-private-header-value")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 400 || strings.Contains(w.Body.String(), "invalid-private-header-value") || repository.calls.Load() != 0 {
		t.Fatal("invalid trusted chain was accepted or reflected")
	}
}

func TestHTTPConfigurationAndBodyBoundary(t *testing.T) {
	service := fixtureService(t, &fakeRepository{failure: ErrDenied})
	config := HTTPConfig{Origin: "https://console.example.com", Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	if _, err := NewHTTP(config, nil); err == nil {
		t.Fatal("nil service accepted")
	}
	config.Origin = "http://console.example.com"
	if _, err := NewHTTP(config, service); err == nil {
		t.Fatal("insecure public origin accepted")
	}
	data, _ := json.Marshal(fixtureRequest(t))
	data = append(data, bytes.Repeat([]byte(" "), protocol.MaxBodyBytes-len(data))...)
	w := httptest.NewRecorder()
	testHTTP(t, service, io.Discard).ServeHTTP(w, requestHTTP(string(data)))
	if w.Code != 401 {
		t.Fatal("a valid JSON request at the exact body limit was rejected by transport validation")
	}
}

func TestHTTPReadinessChecksTrustAndRepository(t *testing.T) {
	repository := &fakeRepository{}
	service := fixtureService(t, repository)
	handler := testHTTP(t, service, io.Discard)
	check := func(method string, status int, body string) {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, "http://127.0.0.1/healthz", nil))
		if w.Code != status || body != "" && w.Body.String() != body || method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("health endpoint returned an incorrect readiness result")
		}
	}
	check("GET", 200, "ok")
	check("HEAD", 200, "")
	check("POST", 405, "")
	repository.failure = errors.New("private-database-diagnostic")
	check("GET", 503, "")
	repository.failure = nil
	service.now = func() time.Time { return service.certs[0].NotAfter.Add(time.Second) }
	check("GET", 503, "")
}
