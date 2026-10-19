package relayhook

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/claim"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

type repositoryFunc func(context.Context, protocol.ClaimPayload) error

func (f repositoryFunc) Authorize(ctx context.Context, identity protocol.ClaimPayload) error {
	return f(ctx, identity)
}

func fixture(t *testing.T, repository Repository, logs io.Writer) (*Server, string) {
	t.Helper()
	signer, err := claim.New("test", map[string][]byte{"test": bytes.Repeat([]byte{19}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := signer.Issue("11111111-1111-4111-8111-111111111111", "abcd1234",
		"22222222-2222-4222-8222-222222222222", time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Peers: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")},
		Logger: slog.New(slog.NewJSONHandler(logs, nil))}, repository, signer)
	if err != nil {
		t.Fatal(err)
	}
	return server, encoded
}

func envelope(operation, encoded string) map[string]any {
	metas := map[string]any{"device_id": "11111111-1111-4111-8111-111111111111", "domain_claim": encoded}
	content := map[string]any{"metas": metas, "privilege_key": "private-frp-authentication-fixture"}
	if operation == "NewProxy" {
		content = map[string]any{"user": map[string]any{"metas": metas, "run_id": "private-run-id-fixture"},
			"proxy_type": "https", "proxy_name": ProxyName(metas["device_id"].(string)), "subdomain": "abcd1234"}
	}
	return map[string]any{"version": "0.1.0", "op": operation, "content": content}
}

func request(t *testing.T, object map[string]any) *http.Request {
	t.Helper()
	data, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://relay.internal"+Path+"?op="+object["op"].(string)+"&version=0.1.0", bytes.NewReader(data))
	r.RemoteAddr = "192.0.2.1:12345"
	r.Header.Set("Content-Type", "application/json")
	return r
}

func outcome(t *testing.T, server *Server, r *http.Request, rejected bool, status int) {
	t.Helper()
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	var result response
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Reject != rejected || w.Code != status ||
		result.Unchange == rejected || rejected && result.RejectReason == "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("incorrect hook response: status=%d", w.Code)
	}
}

func TestSignedIdentityAndFixedDiagnostics(t *testing.T) {
	for _, operation := range []string{"Login", "NewProxy"} {
		var calls atomic.Int32
		var logs bytes.Buffer
		server, encoded := fixture(t, repositoryFunc(func(ctx context.Context, identity protocol.ClaimPayload) error {
			calls.Add(1)
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > Budget || identity.Subdomain != "abcd1234" || identity.TenantID != "22222222-2222-4222-8222-222222222222" {
				t.Error("verified identity or deadline was lost before storage")
			}
			return nil
		}), &logs)
		outcome(t, server, request(t, envelope(operation, encoded)), false, 200)
		if calls.Load() != 1 {
			t.Fatal("valid callback did not reach storage exactly once")
		}
		for _, secret := range []string{encoded, "private-frp-authentication-fixture", "private-run-id-fixture", "11111111-1111-4111-8111-111111111111"} {
			if strings.Contains(logs.String(), secret) {
				t.Fatal("callback values leaked into logs")
			}
		}
	}
	for _, failure := range []error{ErrDenied, errors.New("private-database-diagnostic")} {
		var logs bytes.Buffer
		server, encoded := fixture(t, repositoryFunc(func(context.Context, protocol.ClaimPayload) error { return failure }), &logs)
		outcome(t, server, request(t, envelope("Login", encoded)), true, 200)
		if strings.Contains(logs.String(), "private-database-diagnostic") {
			t.Fatal("dependency error leaked into logs")
		}
	}
}

func TestRejectsBeforeDatabase(t *testing.T) {
	for _, test := range []struct {
		name, operation string
		status          int
		mutate          func(map[string]any, *http.Request)
	}{
		{"untrusted_peer", "Login", 403, func(_ map[string]any, r *http.Request) {
			r.RemoteAddr = "[2001:db8::2]:1"
			r.Header.Set("X-Forwarded-For", "192.0.2.1")
		}},
		{"invalid_peer", "Login", 403, func(_ map[string]any, r *http.Request) { r.RemoteAddr = "invalid" }},
		{"public_route", "Login", 404, func(_ map[string]any, r *http.Request) { r.URL.Path = "/api/v1/devices/enroll" }},
		{"encoded_path", "Login", 404, func(_ map[string]any, r *http.Request) { r.URL.RawPath = "/api/v1/frp/%68ooks" }},
		{"method", "Login", 405, func(_ map[string]any, r *http.Request) { r.Method = "GET" }},
		{"media", "Login", 200, func(_ map[string]any, r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
		{"encoding", "Login", 200, func(_ map[string]any, r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"query_missing", "Login", 200, func(_ map[string]any, r *http.Request) { r.URL.RawQuery = "" }},
		{"query_op", "Login", 200, func(_ map[string]any, r *http.Request) { r.URL.RawQuery = "op=NewProxy&version=0.1.0" }},
		{"query_repeated", "Login", 200, func(_ map[string]any, r *http.Request) { r.URL.RawQuery += "&op=Login" }},
		{"query_extra", "Login", 200, func(_ map[string]any, r *http.Request) { r.URL.RawQuery += "&token=private-query-fixture" }},
		{"version", "Login", 200, func(o map[string]any, _ *http.Request) { o["version"] = "1.0.0" }},
		{"operation", "Login", 200, func(o map[string]any, _ *http.Request) { o["op"] = "private-unknown-operation" }},
		{"content_null", "Login", 200, func(o map[string]any, _ *http.Request) { o["content"] = nil }},
		{"missing_claim", "Login", 200, func(o map[string]any, _ *http.Request) {
			delete(o["content"].(map[string]any)["metas"].(map[string]any), "domain_claim")
		}},
		{"invalid_signature", "Login", 200, func(o map[string]any, _ *http.Request) {
			o["content"].(map[string]any)["metas"].(map[string]any)["domain_claim"] = "invalid-private-claim"
		}},
		{"identity_mismatch", "Login", 200, func(o map[string]any, _ *http.Request) {
			o["content"].(map[string]any)["metas"].(map[string]any)["device_id"] = "other-device"
		}},
		{"user_null", "NewProxy", 200, func(o map[string]any, _ *http.Request) { o["content"].(map[string]any)["user"] = nil }},
		{"proxy_type", "NewProxy", 200, func(o map[string]any, _ *http.Request) { o["content"].(map[string]any)["proxy_type"] = "tcp" }},
		{"proxy_name", "NewProxy", 200, func(o map[string]any, _ *http.Request) {
			o["content"].(map[string]any)["proxy_name"] = ProxyName("33333333-3333-4333-8333-333333333333")
		}},
		{"legacy_proxy_name", "NewProxy", 200, func(o map[string]any, _ *http.Request) { o["content"].(map[string]any)["proxy_name"] = "nethub-webgui" }},
		{"subdomain", "NewProxy", 200, func(o map[string]any, _ *http.Request) { o["content"].(map[string]any)["subdomain"] = "another1" }},
		{"custom_domain", "NewProxy", 200, func(o map[string]any, _ *http.Request) {
			o["content"].(map[string]any)["custom_domains"] = []string{"console.example.com"}
		}},
		{"custom_wildcard", "NewProxy", 200, func(o map[string]any, _ *http.Request) {
			o["content"].(map[string]any)["custom_domains"] = []string{"*.example.com"}
		}},
		{"custom_domain_type", "NewProxy", 200, func(o map[string]any, _ *http.Request) { o["content"].(map[string]any)["custom_domains"] = "" }},
		{"group", "NewProxy", 200, func(o map[string]any, _ *http.Request) { o["content"].(map[string]any)["group"] = "shared" }},
		{"group_key", "NewProxy", 200, func(o map[string]any, _ *http.Request) {
			o["content"].(map[string]any)["group_key"] = "private-group-fixture"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			var logs bytes.Buffer
			server, encoded := fixture(t, repositoryFunc(func(context.Context, protocol.ClaimPayload) error { calls.Add(1); return nil }), &logs)
			object := envelope(test.operation, encoded)
			r := request(t, object)
			test.mutate(object, r)
			data, _ := json.Marshal(object)
			r.Body = io.NopCloser(bytes.NewReader(data))
			outcome(t, server, r, true, test.status)
			if calls.Load() != 0 || strings.Contains(logs.String(), encoded) || strings.Contains(logs.String(), "private-") {
				t.Fatal("rejection reached storage or logged callback values")
			}
		})
	}
}

func TestDuplicateKeysSizeAndCapacity(t *testing.T) {
	var calls atomic.Int32
	server, encoded := fixture(t, repositoryFunc(func(context.Context, protocol.ClaimPayload) error { calls.Add(1); return nil }), io.Discard)
	object := envelope("Login", encoded)
	data, _ := json.Marshal(object)
	for _, body := range []string{strings.Replace(string(data), `"device_id":`, `"\u0064evice_id":"other","device_id":`, 1),
		strings.Repeat(" ", 65537), `{"extension":{"x":1,"x":2}}`} {
		r := request(t, object)
		r.Body = io.NopCloser(strings.NewReader(body))
		outcome(t, server, r, true, 200)
	}
	for range cap(server.workers) {
		server.workers <- struct{}{}
	}
	outcome(t, server, request(t, object), true, 200)
	if calls.Load() != 0 {
		t.Fatal("invalid or saturated callback reached storage")
	}
}

func TestRepositoryDeadlineDenies(t *testing.T) {
	server, encoded := fixture(t, repositoryFunc(func(ctx context.Context, _ protocol.ClaimPayload) error {
		<-ctx.Done()
		return nil
	}), io.Discard)
	started := time.Now()
	outcome(t, server, request(t, envelope("Login", encoded)), true, 200)
	if time.Since(started) > 1500*time.Millisecond {
		t.Fatal("expired callback exceeded its response budget")
	}
}

func TestSlowBodyCannotHoldTheCallback(t *testing.T) {
	var calls atomic.Int32
	handler, _ := fixture(t, repositoryFunc(func(context.Context, protocol.ClaimPayload) error { calls.Add(1); return nil }), io.Discard)
	server := httptest.NewServer(handler)
	defer server.Close()
	connection, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	started := time.Now()
	_, err = io.WriteString(connection, "POST "+Path+"?op=Login&version=0.1.0 HTTP/1.1\r\nHost: relay.internal\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{")
	if err != nil {
		t.Fatal(err)
	}
	result, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: "POST"})
	if err == nil {
		defer result.Body.Close()
		var decision response
		if json.NewDecoder(result.Body).Decode(&decision) != nil || !decision.Reject {
			t.Fatal("slow body received an invalid or allowing decision")
		}
	}
	if calls.Load() != 0 || time.Since(started) > 1500*time.Millisecond {
		t.Fatal("incomplete body reached storage or held the hook connection")
	}
}

func TestPeerConfigurationIsRequiredAndSnapshotted(t *testing.T) {
	server, encoded := fixture(t, repositoryFunc(func(context.Context, protocol.ClaimPayload) error { return nil }), io.Discard)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	for _, peers := range [][]netip.Addr{nil, {netip.Addr{}}, {netip.IPv4Unspecified()},
		{netip.MustParseAddr("::ffff:" + netip.IPv4Unspecified().String())}, {netip.MustParseAddr("fe80::1%zone")}} {
		if _, err := New(Config{Peers: peers, Logger: logger}, server.repository, server.signer); err == nil {
			t.Fatal("missing or invalid peer restriction accepted")
		}
	}
	peers := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	snapshot, err := New(Config{Peers: peers, Logger: logger}, server.repository, server.signer)
	if err != nil {
		t.Fatal(err)
	}
	peers[0] = netip.MustParseAddr("2001:db8::2")
	outcome(t, snapshot, request(t, envelope("Login", encoded)), false, 200)
	r := request(t, envelope("Login", encoded))
	r.RemoteAddr = "[2001:db8::2]:1"
	outcome(t, snapshot, r, true, 403)
}
