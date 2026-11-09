package guiacme

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func coldWitnessAllowsHTTP(r *http.Request, expectedPeer, assignedHost string) bool {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	return err == nil && peer == expectedPeer && (r.Host == assignedHost || r.Host == assignedHost+":80") &&
		r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/")
}

func TestColdWitnessHTTPAuthorityAdmission(t *testing.T) {
	const host = "abcdefgh.devices.example.test"
	const path = "/.well-known/acme-challenge/aaaaaaaaaaaaaaaaaaaaaa"
	for _, test := range []struct {
		name, authority, method, path, peer string
		allowed                             bool
	}{
		{"bare host", host, "GET", path, "127.0.0.1", true},
		{"explicit default port", host + ":80", "GET", path, "127.0.0.1", true},
		{"other port", host + ":8443", "GET", path, "127.0.0.1", false},
		{"noncanonical port", host + ":080", "GET", path, "127.0.0.1", false},
		{"other host", "other.devices.example.test", "GET", path, "127.0.0.1", false},
		{"host suffix", host + ".other.test", "GET", path, "127.0.0.1", false},
		{"other peer", host, "GET", path, "127.0.0.2", false},
		{"other method", host, "POST", path, "127.0.0.1", false},
		{"other path", host, "GET", "/unrelated", "127.0.0.1", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			seen := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Host
				if !coldWitnessAllowsHTTP(r, test.peer, host) {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "http://"))
			}}
			defer transport.CloseIdleConnections()
			request, err := http.NewRequest(test.method, "http://"+test.authority+test.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if actual := <-seen; actual != test.authority {
				t.Fatalf("actual HTTP authority changed: %q", actual)
			}
			want := http.StatusNotFound
			if test.allowed {
				want = http.StatusOK
			}
			if response.StatusCode != want {
				t.Fatalf("admission status=%d want=%d", response.StatusCode, want)
			}
		})
	}
}
