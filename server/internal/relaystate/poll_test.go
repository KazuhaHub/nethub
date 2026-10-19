package relaystate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

const deviceID = "11111111-1111-4111-8111-111111111111"
const password = "public-test-only-administrator-password"

type repositoryFunc func(context.Context, []Observation) error

func (f repositoryFunc) Observe(ctx context.Context, values []Observation) error {
	return f(ctx, values)
}

func proxy() map[string]any {
	return map[string]any{"name": relayhook.ProxyName(deviceID), "status": "online",
		"conf": map[string]any{"name": relayhook.ProxyName(deviceID), "type": "https", "subdomain": "abcd1234",
			"loadBalancer": map[string]any{}}}
}

func payload(t *testing.T, values ...map[string]any) []byte {
	t.Helper()
	if values == nil {
		values = []map[string]any{}
	}
	data, err := json.Marshal(map[string]any{"proxies": values})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newPoller(t *testing.T, origin string, repository Repository, output io.Writer) *Poller {
	t.Helper()
	poller, err := New(Config{Origin: origin, User: "test-admin", Password: password,
		Logger: slog.New(slog.NewJSONHandler(output, nil))}, repository)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(poller.client.CloseIdleConnections)
	return poller
}

func TestAuthenticatedReadOnlyObservation(t *testing.T) {
	var calls atomic.Int32
	data := payload(t, proxy(), map[string]any{"name": "manual-proxy", "status": "online", "conf": nil},
		map[string]any{"name": "old-proxy", "status": "offline", "conf": nil})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, secret, ok := r.BasicAuth()
		if !ok || user != "test-admin" || secret != password || r.Method != http.MethodGet || r.URL.RequestURI() != "/api/proxy/https" ||
			r.Header.Get("Accept-Encoding") != "identity" || r.ContentLength != 0 || r.Header.Get("Cookie") != "" {
			t.Error("unexpected admin authentication or mutation request")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	defer server.Close()
	poller := newPoller(t, server.URL, repositoryFunc(func(ctx context.Context, values []Observation) error {
		calls.Add(1)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second || len(values) != 1 || values[0] != (Observation{DeviceID: deviceID, Subdomain: "abcd1234"}) {
			t.Error("observation identity, filtering or storage budget is incorrect")
		}
		return nil
	}), io.Discard)
	if poller.interval != 15*time.Second || poller.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("production cadence or direct-connection policy changed")
	}
	if err := poller.Poll(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatal("valid authenticated admin observation did not reach storage")
	}
}

func TestInvalidResponseCannotRefreshDevices(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"type", func(p map[string]any) { p["conf"].(map[string]any)["type"] = "http" }},
		{"name", func(p map[string]any) { p["conf"].(map[string]any)["name"] = "another-device" }},
		{"domain", func(p map[string]any) { p["conf"].(map[string]any)["subdomain"] = "invalid.domain" }},
		{"custom_domains", func(p map[string]any) { p["conf"].(map[string]any)["customDomains"] = []string{"console.example.com"} }},
		{"group", func(p map[string]any) {
			p["conf"].(map[string]any)["loadBalancer"] = map[string]string{"group": "shared"}
		}},
		{"null_config", func(p map[string]any) { p["conf"] = nil }},
		{"status", func(p map[string]any) { p["status"] = "unknown" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := proxy()
			test.mutate(value)
			if _, err := parse(bytes.NewReader(payload(t, value))); !errors.Is(err, ErrResponse) {
				t.Fatal("unsafe or malformed online route accepted")
			}
		})
	}
	for _, data := range [][]byte{[]byte(`{"proxies":null}`), []byte(`{"Proxies":[]}`), []byte(`{"proxies":[],"proxies":[]}`),
		[]byte(strings.Repeat(" ", maxBody+1)), payload(t, proxy(), proxy())} {
		if _, err := parse(bytes.NewReader(data)); !errors.Is(err, ErrResponse) {
			t.Fatal("ambiguous or oversized response accepted")
		}
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"proxies":[`)
	}))
	defer server.Close()
	poller := newPoller(t, server.URL, repositoryFunc(func(context.Context, []Observation) error { calls.Add(1); return nil }), io.Discard)
	if err := poller.Poll(context.Background()); !errors.Is(err, ErrResponse) || calls.Load() != 0 {
		t.Fatal("truncated admin response refreshed devices")
	}
}

func TestAdminFailureRedirectAndProxyIsolation(t *testing.T) {
	var forwarded atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded.Add(1) }))
	defer trap.Close()
	t.Setenv("HTTP_PROXY", trap.URL)
	t.Setenv("HTTPS_PROXY", trap.URL)
	for _, status := range []int{301, 302, 401, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", trap.URL)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, password)
		}))
		var calls atomic.Int32
		poller := newPoller(t, server.URL, repositoryFunc(func(context.Context, []Observation) error { calls.Add(1); return nil }), io.Discard)
		if err := poller.Poll(context.Background()); !errors.Is(err, ErrResponse) || calls.Load() != 0 {
			t.Error("admin error or redirect was accepted")
		}
		server.Close()
	}
	if forwarded.Load() != 0 {
		t.Fatal("admin credentials reached a redirect target or environment proxy")
	}
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS reached HTTP") }))
	defer untrusted.Close()
	poller := newPoller(t, untrusted.URL, repositoryFunc(func(context.Context, []Observation) error { return nil }), io.Discard)
	if err := poller.Poll(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatal("untrusted admin TLS was accepted")
	}
}

func TestPrivateAddressAndOriginRules(t *testing.T) {
	for _, addresses := range [][]netip.Addr{nil, {netip.MustParseAddr("192.0.2.1")},
		{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")}, {netip.MustParseAddr("fe80::1%zone")}, {netip.IPv4Unspecified()}} {
		if allPrivate(addresses) {
			t.Fatal("nonprivate or ambiguous DNS results accepted")
		}
	}
	if !allPrivate([]netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fd00::1")}) {
		t.Fatal("valid private addresses rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if connection, err := privateDial(ctx, "tcp", "192.0.2.1:7500"); connection != nil || !errors.Is(err, ErrTransport) {
		t.Fatal("public admin socket was dialed")
	}
	for _, origin := range []string{"http://192.0.2.1:7500", "http://user:private@127.0.0.1:7500", "http://127.0.0.1:7500/path",
		"http://127.0.0.1:7500?token=private", "http://127.0.0.1", "ftp://127.0.0.1:7500"} {
		if _, err := New(Config{Origin: origin, User: "test", Password: password, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))},
			repositoryFunc(func(context.Context, []Observation) error { return nil })); err == nil || strings.Contains(err.Error(), "token=private") {
			t.Fatal("unsafe admin origin accepted or exposed in diagnostics")
		}
	}
}

func TestRunCadenceCancellationAndSafeRecovery(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"proxies":[]}`)
	}))
	defer server.Close()
	var output bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	poller := newPoller(t, server.URL, repositoryFunc(func(context.Context, []Observation) error {
		attempt := calls.Add(1)
		if attempt <= 2 {
			return fmt.Errorf("private database diagnostic: %s", password)
		}
		if attempt >= 4 {
			cancel()
		}
		return nil
	}), &output)
	poller.interval = 10 * time.Millisecond
	done := make(chan struct{})
	go func() { poller.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("observation loop did not stop")
	}
	if calls.Load() != 4 || strings.Count(output.String(), "Relay observation unavailable") != 1 ||
		strings.Count(output.String(), "Relay observation resumed") != 1 || strings.Contains(output.String(), password) ||
		strings.Contains(output.String(), "private database diagnostic") {
		t.Fatal("observation retry or safe transition logging is incorrect")
	}
}

func TestResponseArrayBoundaryAndOfflineEntries(t *testing.T) {
	values := make([]map[string]any, 0, MaxProxies+1)
	for i := 0; i < MaxProxies+1; i++ {
		values = append(values, map[string]any{"name": fmt.Sprintf("manual-%d", i), "status": "offline", "conf": nil})
	}
	if observed, err := parse(bytes.NewReader(payload(t, values[:MaxProxies]...))); err != nil || len(observed) != 0 {
		t.Fatal("valid bounded offline list rejected or marked online")
	}
	if _, err := parse(bytes.NewReader(payload(t, values...))); err == nil {
		t.Fatal("oversized proxy array accepted")
	}
	if observed, err := parse(bytes.NewReader(payload(t))); err != nil || len(observed) != 0 {
		t.Fatal("empty active set was not accepted")
	}
}

func TestResponseEncodingAndCancellationCannotRefreshDevices(t *testing.T) {
	for _, mode := range []string{"compressed", "duplicate_media", "slow_body"} {
		t.Run(mode, func(t *testing.T) {
			data := payload(t, proxy())
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
				case "duplicate_media":
					w.Header().Add("Content-Type", "application/json")
				case "slow_body":
					_, _ = io.WriteString(w, `{"proxies":[`)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				_, _ = w.Write(data)
			}))
			defer server.Close()
			var calls atomic.Int32
			poller := newPoller(t, server.URL, repositoryFunc(func(context.Context, []Observation) error { calls.Add(1); return nil }), io.Discard)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			started := time.Now()
			if err := poller.Poll(ctx); err == nil || calls.Load() != 0 || time.Since(started) > time.Second {
				t.Fatal("unsupported encoding or stalled response reached storage or ignored cancellation")
			}
		})
	}
	data, err := json.Marshal(Config{Origin: "http://127.0.0.1:7500", User: "private-admin-user", Password: password})
	if err != nil || bytes.Contains(data, []byte(password)) || bytes.Contains(data, []byte("private-admin-user")) {
		t.Fatal("serialized observer configuration contains admin credentials")
	}
}
