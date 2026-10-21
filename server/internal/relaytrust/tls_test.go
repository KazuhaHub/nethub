package relaytrust

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaycert"
)

func TestOverlapTrustAuthenticatesBothRelayAuthorities(t *testing.T) {
	now := time.Now().UTC()
	old, err := relaycert.Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := relaycert.Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	serve := func(m relaycert.Material) string {
		t.Helper()
		pair, err := tls.X509KeyPair(m.Certificate, m.Key)
		if err != nil {
			t.Fatal(err)
		}
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		s.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
		s.StartTLS()
		t.Cleanup(s.Close)
		return s.URL
	}
	oldURL, nextURL := serve(old), serve(next)
	for _, test := range []struct {
		name, pem string
		old, next bool
	}{
		{"old", string(old.CA), true, false},
		{"overlap", string(old.CA) + string(next.CA), true, true},
		{"next", string(next.CA), false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			bundle, err := Parse(test.pem, now)
			if err != nil {
				t.Fatal(err)
			}
			certificates, err := bundle.Certificates()
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			for _, certificate := range certificates {
				roots.AddCert(certificate)
			}
			transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "relay.example.test", MinVersion: tls.VersionTLS12}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			for _, peer := range []struct {
				url     string
				allowed bool
			}{{oldURL, test.old}, {nextURL, test.next}} {
				response, err := client.Get(peer.url)
				if response != nil {
					response.Body.Close()
				}
				if (err == nil) != peer.allowed || err == nil && response.StatusCode != http.StatusOK {
					t.Fatal("relay authority authentication differed from staged trust")
				}
			}
			wrongName := transport.Clone()
			wrongName.TLSClientConfig.ServerName = "other.example.test"
			defer wrongName.CloseIdleConnections()
			if response, err := (&http.Client{Transport: wrongName, Timeout: 2 * time.Second}).Get(nextURL); err == nil {
				response.Body.Close()
				t.Fatal("overlap bypassed relay hostname authentication")
			}
		})
	}
}
