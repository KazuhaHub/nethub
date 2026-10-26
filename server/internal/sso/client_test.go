package sso

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testOutbound(t *testing.T, hosts ...string) *Outbound {
	t.Helper()
	o, err := NewOutbound(hosts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.CloseIdleConnections)
	return o
}

func TestPrivateAuthority(t *testing.T) {
	for input, want := range map[string]string{
		"IDP.Example": "idp.example:443", "idp.example:8443": "idp.example:8443",
		"[2001:4860::1]": "[2001:4860::1]:443", "[::ffff:127.0.0.1]:8443": "127.0.0.1:8443",
	} {
		got, err := NormalizePrivateHost(input)
		if err != nil || got != want {
			t.Fatalf("%q: %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"", "https://idp.example", "*.example", "idp.example/path", "idp.example?x", "user@idp.example", "idp.example.", "idp.example:", "idp.example:0", "idp.example:65536", "idp.example:0443", "[fe80::1%en0]", "[idp.example]", "[127.0.0.1]", "a..example", "-a.example", "a_.example", "idp.example\n", "idp.example#x"} {
		if _, err := NormalizePrivateHost(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
	if _, err := NewOutbound(make([]string, 17)); err == nil {
		t.Fatal("unbounded exceptions")
	}
}

func TestPublicAddressPolicy(t *testing.T) {
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8"} {
		if !publicSSOAddress(netip.MustParseAddr(value)) {
			t.Fatalf("public rejected: %s", value)
		}
	}
	for _, value := range []string{"0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "192.0.0.9", "192.0.2.1", "192.88.99.1", "198.18.1.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "168.63.129.16", "::", "::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "64:ff9b:1::1", "100::1", "2001::1", "2001:db8::1", "2002:7f00:1::1", "3fff::1", "fc00::1", "fe80::1", "fec0::1", "ff02::1"} {
		if publicSSOAddress(netip.MustParseAddr(value)) {
			t.Fatalf("special address accepted: %s", value)
		}
	}
}

func TestDNSWholeAnswerBeforeDial(t *testing.T) {
	for _, addresses := range [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("::ffff:127.0.0.1"), netip.MustParseAddr("8.8.8.8")},
		nil, make([]netip.Addr, 17), {netip.MustParseAddr("fe80::1%eth0")},
	} {
		o := testOutbound(t)
		o.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return addresses, nil }
		o.dial = func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("dialed rejected DNS answer")
			return nil, nil
		}
		if _, err := o.dialContext(context.Background(), "tcp", "idp.example:443"); !errors.Is(err, ErrOutbound) {
			t.Fatal(err)
		}
	}
}

func TestDialPinsOneResolutionAndTriesValidatedAddresses(t *testing.T) {
	o := testOutbound(t)
	lookups := 0
	o.lookup = func(_ context.Context, network, host string) ([]netip.Addr, error) {
		lookups++
		if network != "ip" || host != "idp.example" {
			t.Fatal(network, host)
		}
		if lookups > 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("2606:4700::1111"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
	}
	var attempts []string
	left, right := net.Pipe()
	defer right.Close()
	o.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		attempts = append(attempts, address)
		if address == "8.8.8.8:443" {
			return nil, errors.New("route unavailable")
		}
		if network != "tcp" || address != "1.1.1.1:443" {
			t.Fatal(network, address)
		}
		return left, nil
	}
	conn, err := o.dialContext(context.Background(), "tcp", "idp.example:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if lookups != 1 || len(attempts) != 2 {
		t.Fatal(lookups, attempts)
	}
	if _, err := o.dialContext(context.Background(), "tcp", "idp.example:443"); err == nil {
		t.Fatal("accepted rebinding on next connection")
	}
	if len(attempts) != 2 {
		t.Fatal("dialed rebinding address")
	}
}

func TestPrivateExceptionIsExactAuthority(t *testing.T) {
	o := testOutbound(t, "idp.example:8443")
	o.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	}
	if err := o.ValidateEndpoint(context.Background(), "https://idp.example:8443/issuer"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"https://idp.example/issuer", "https://sub.idp.example:8443/", "http://idp.example:8443/", "https://idp.example:8443/#fragment", "https://user@idp.example:8443/"} {
		if err := o.ValidateEndpoint(context.Background(), value); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
	o = testOutbound(t, "0.0.0.0", "224.0.0.1")
	for _, value := range []string{"https://0.0.0.0/", "https://224.0.0.1/"} {
		if err := o.ValidateEndpoint(context.Background(), value); err == nil {
			t.Fatal("exception accepted non-unicast")
		}
	}
}

func tlsOutbound(t *testing.T, server *httptest.Server) *Outbound {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	o, err := newOutbound([]string{strings.TrimPrefix(server.URL, "https://")}, roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.CloseIdleConnections)
	return o
}

func TestHTTPSPolicyAndBoundedReads(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/oversized":
			io.WriteString(w, strings.Repeat("x", maxSSOResponse+1))
		case "/compressed":
			w.Header().Set("Content-Encoding", "gzip")
			io.WriteString(w, "opaque")
		case "/redirect":
			w.Header().Set("Location", "/ok")
			w.WriteHeader(http.StatusFound)
		case "/private-redirect":
			w.Header().Set("Location", "https://127.0.0.1/")
			w.WriteHeader(http.StatusFound)
		default:
			io.WriteString(w, "ok")
		}
	}))
	defer server.Close()
	o := tlsOutbound(t, server)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	if o.base.Proxy != nil {
		t.Fatal("ambient proxy enabled")
	}
	for _, path := range []string{"/ok", "/redirect"} {
		response, err := o.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "ok" {
			t.Fatal(string(body), err)
		}
	}
	for _, path := range []string{"/oversized", "/compressed", "/private-redirect"} {
		if response, err := o.Client().Get(server.URL + path); err == nil {
			response.Body.Close()
			t.Fatalf("accepted %s", path)
		}
	}
	before := calls.Load()
	if _, err := o.Client().Post(server.URL+"/redirect", "application/x-www-form-urlencoded", strings.NewReader("code=private")); err == nil {
		t.Fatal("token redirect accepted")
	}
	if calls.Load() != before+1 {
		t.Fatal("token POST replayed")
	}
	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	request.Host = "other.example"
	if _, err := o.RoundTrip(request); err != ErrOutbound {
		t.Fatal("Host override accepted", err)
	}
	request, _ = http.NewRequest(http.MethodDelete, server.URL, nil)
	if _, err := o.RoundTrip(request); err != ErrOutbound {
		t.Fatal("method accepted", err)
	}
	// An allowed network destination still requires a trusted TLS certificate.
	untrusted := testOutbound(t, strings.TrimPrefix(server.URL, "https://"))
	if _, err := untrusted.Client().Get(server.URL); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	blocked := testOutbound(t)
	if _, err := blocked.Client().Get(server.URL); err == nil {
		t.Fatal("loopback accepted by default")
	}
}

func TestOutboundCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	o := tlsOutbound(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	started := time.Now()
	if _, err := o.Client().Do(request); err == nil || time.Since(started) > 2*time.Second {
		t.Fatal("request cancellation not bounded", err)
	}
}
