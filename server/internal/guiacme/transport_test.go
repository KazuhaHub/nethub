package guiacme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportConfinesEveryRequest(t *testing.T) {
	var seen atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		_, _ = w.Write([]byte("bounded response"))
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := newTransport(map[string]bool{server.URL: true}, roots)
	defer transport.base.CloseIdleConnections()
	if transport.base.Proxy != nil || transport.base.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("proxy or TLS verification disabled")
	}
	for _, method := range []string{"GET", "HEAD", "POST"} {
		r, _ := http.NewRequest(method, server.URL+"/allowed", nil)
		response, err := transport.client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	if seen.Load() != 3 {
		t.Fatal("allowed requests not served")
	}
	for _, value := range []string{"http://" + strings.TrimPrefix(server.URL, "https://"), "https://other.example.test/account", server.URL + "/path#fragment", strings.Replace(server.URL, "https://", "https://user:secret@", 1)} {
		r, err := http.NewRequest("POST", value, nil)
		if err != nil {
			t.Fatal(err)
		}
		if response, err := transport.RoundTrip(r); err != ErrRemote || response != nil {
			t.Fatal("unapproved target accepted")
		}
	}
	r, _ := http.NewRequest("POST", server.URL, nil)
	r.Host = "other.example.test"
	if _, err := transport.RoundTrip(r); err != ErrRemote {
		t.Fatal("Host override accepted")
	}
	r, _ = http.NewRequest("DELETE", server.URL, nil)
	if _, err := transport.RoundTrip(r); err != ErrRemote {
		t.Fatal("unexpected method accepted")
	}
	if seen.Load() != 3 {
		t.Fatal("disallowed request reached server")
	}
}

func TestTransportRejectsRedirectBodyAndEncoding(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, destination.URL+"/private", http.StatusFound)
		case "/declared":
			w.Header().Set("Content-Length", "9999999")
		case "/chunked":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte(strings.Repeat("x", maxResponse+1)))
		case "/encoded":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write([]byte("compressed"))
		case "/headers":
			w.Header().Set("X-Oversized", strings.Repeat("x", 70<<10))
		case "/boundary":
			_, _ = w.Write([]byte(strings.Repeat("x", maxResponse)))
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	roots.AddCert(destination.Certificate())
	transport := newTransport(map[string]bool{server.URL: true, destination.URL: true}, roots)
	defer transport.base.CloseIdleConnections()
	for _, path := range []string{"redirect", "declared", "chunked", "encoded", "headers"} {
		r, _ := http.NewRequest("GET", server.URL+"/"+path, nil)
		response, err := transport.client().Do(r)
		if err == nil || response != nil {
			t.Fatalf("accepted %s", path)
		}
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect was followed even to an approved origin")
	}
	r, _ := http.NewRequest("GET", server.URL+"/boundary", nil)
	response, err := transport.client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || len(body) != maxResponse {
		t.Fatal("bounded response changed")
	}
}

func TestCancelledTransportClosesSlowBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := newTransport(map[string]bool{server.URL: true}, roots)
	defer transport.base.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	started := time.Now()
	if _, err := transport.client().Do(r); err == nil || time.Since(started) > 2*time.Second {
		t.Fatal("slow body ignored deadline")
	}
}

func TestConfigurationRejectsUnboundOrMalformedInputs(t *testing.T) {
	_, baseline := fixture(t)
	for _, value := range []string{"", "http://ca.example.test/directory", "https://user:secret@ca.example.test/directory", "https://ca.example.test/directory#secret", "https://CA.example.test/directory", "https://ca.example.test:/directory", "https://ca.example.test./directory", "https://ca.example.test:99999/directory", "https://ca.example.test/" + strings.Repeat("x", 2048)} {
		config := baseline
		config.DirectoryURL = value
		if c, err := New(config); err != ErrConfig || c != nil {
			t.Fatal("malformed directory accepted")
		}
	}
	for _, value := range []string{"https://other.example.test/", "https://other.example.test?", "https://other.example.test/path", "https://other.example.test#fragment", "http://other.example.test"} {
		config := baseline
		config.AdditionalOrigins = []string{value}
		if c, err := New(config); err != ErrConfig || c != nil {
			t.Fatal("malformed origin accepted")
		}
	}
	for _, value := range []string{"Admin <admin@example.test>", "admin@example.test\n", "not an email"} {
		config := baseline
		config.ContactEmail = value
		if c, err := New(config); err != ErrConfig || c != nil {
			t.Fatal("malformed contact accepted")
		}
	}
	for _, mode := range []string{"nil", "other-curve", "wrong-public"} {
		config := baseline
		switch mode {
		case "nil":
			config.Key = nil
		case "other-curve":
			config.Key, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case "wrong-public":
			copy := *config.Key
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			copy.PublicKey = other.PublicKey
			config.Key = &copy
		}
		if c, err := New(config); err != ErrConfig || c != nil {
			t.Fatal("invalid signing key accepted")
		}
	}
}

func TestExplicitAdditionalOriginAndTransportSnapshot(t *testing.T) {
	f, config := fixture(t)
	config.AdditionalOrigins = []string{"https://secondary.example.test"}
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.transport.allowed("https://secondary.example.test/order/1") || c.transport.allowed("https://secondary.example.test:443/order/1") {
		t.Fatal("explicit origin policy")
	}
	// Mutating caller-owned configuration must not change the client's key or roots.
	encoded, _ := x509.MarshalECPrivateKey(config.Key)
	expected, _ := x509.ParseECPrivateKey(encoded)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	config.Key.D.Set(other.D)
	config.Key.X.Set(other.X)
	config.Key.Y.Set(other.Y)
	f.key = expected
	if c.transport.base.TLSClientConfig.RootCAs == config.Roots || !c.transport.base.TLSClientConfig.RootCAs.Equal(config.Roots) {
		t.Fatal("trust configuration was not snapshotted")
	}
	if _, err := c.EnsureAccount(context.Background(), Registration{AllowCreate: true, AcceptedTermsURL: f.terms}); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(f.server.URL)
	if !c.transport.origins[u.Scheme+"://"+u.Host] {
		t.Fatal("directory origin missing")
	}
}
