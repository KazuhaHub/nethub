package relaycert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreateAndVerifiedHandshake(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	m, err := Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := certificate(m.CA)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certificate(m.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.NotAfter.Equal(now.AddDate(10, 0, 0)) || !leaf.NotAfter.Equal(now.AddDate(1, 0, 0)) ||
		!ca.PermittedDNSDomainsCritical || len(ca.PermittedDNSDomains) != 1 || ca.PermittedDNSDomains[0] != "relay.example.test" {
		t.Fatal("unexpected lifetime or authority scope")
	}
	encoded, err := json.Marshal(m)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("material must not serialize")
	}
	pair, err := tls.X509KeyPair(m.Certificate, m.Key)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "relay.example.test", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ok" || len(response.TLS.VerifiedChains) != 1 {
		t.Fatal("verified handshake failed")
	}
}

func TestRenewalPreservesAuthorityAndRotatesLeaf(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	m, err := Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, when := range []time.Time{now.AddDate(0, 10, 0), now.AddDate(9, 11, 0)} {
		t.Run(when.Format("2006-01-02"), func(t *testing.T) {
			next, err := Renew(m.CA, m.CAKey, "relay.example.test", when)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(m.CA, next.CA) || !bytes.Equal(m.CAKey, next.CAKey) || bytes.Equal(m.Key, next.Key) || bytes.Equal(m.Certificate, next.Certificate) {
				t.Fatal("renewal must preserve authority and rotate leaf/key")
			}
			leaf, _ := certificate(next.Certificate)
			root, _ := certificate(next.CA)
			if leaf.NotAfter.After(root.NotAfter) {
				t.Fatal("leaf outlives authority")
			}
			next.CA[0] ^= 1
			if bytes.Equal(next.CA, m.CA) {
				t.Fatal("authority buffers alias")
			}
		})
	}
}

func TestRejectInvalidMaterial(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	m, err := Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Create("other.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		ca, leaf, key []byte
		host          string
		when          time.Time
	}{
		{"wrong authority", other.CA, m.Certificate, m.Key, "relay.example.test", now},
		{"wrong key", m.CA, m.Certificate, other.Key, "relay.example.test", now},
		{"wrong hostname", m.CA, m.Certificate, m.Key, "other.example.test", now},
		{"expired", m.CA, m.Certificate, m.Key, "relay.example.test", now.AddDate(1, 0, 0)},
		{"not yet valid", m.CA, m.Certificate, m.Key, "relay.example.test", now.Add(-6 * time.Minute)},
		{"multiple roots", append(bytes.Clone(m.CA), other.CA...), m.Certificate, m.Key, "relay.example.test", now},
		{"trailing garbage", m.CA, append(bytes.Clone(m.Certificate), []byte("garbage")...), m.Key, "relay.example.test", now},
		{"empty key", m.CA, m.Certificate, nil, "relay.example.test", now},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(Check(tt.ca, tt.leaf, tt.key, tt.host, tt.when), ErrMaterial) {
				t.Fatal("invalid material accepted")
			}
		})
	}
	for _, host := range []string{"", "localhost", "Relay.example.test", "*.example.test", "127.0.0.1", "relay.example.test.", "-bad.example.test"} {
		if _, err := Create(host, now); !errors.Is(err, ErrMaterial) {
			t.Fatal("invalid identity accepted")
		}
	}
	for _, tt := range []struct {
		key  []byte
		host string
		when time.Time
	}{
		{other.CAKey, "relay.example.test", now}, {m.CAKey, "outside.example.test", now},
		{m.CAKey, "relay.example.test", now.AddDate(10, 0, 0)}, {m.CAKey, "relay.example.test", time.Time{}},
	} {
		if _, err := Renew(m.CA, tt.key, tt.host, tt.when); !errors.Is(err, ErrMaterial) {
			t.Fatal("invalid renewal accepted")
		}
	}
}
