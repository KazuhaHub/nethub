package main

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDoctorTLSVerifiesChainHostnameAndValidityWithoutHTTP(t *testing.T) {
	requests := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests <- struct{}{} }))
	defer server.Close()
	certificate := server.Certificate()
	trust := x509.NewCertPool()
	trust.AddCert(certificate)
	address := strings.TrimPrefix(server.URL, "https://")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := certificate.NotAfter.Add(-90 * 24 * time.Hour)
	remaining, err := verifyConsoleTLS(ctx, address, "127.0.0.1", trust, now)
	if err != nil || remaining != 90*24*time.Hour {
		t.Fatal("trusted console certificate lifetime was not verified", err)
	}
	for _, test := range []struct {
		name  string
		roots *x509.CertPool
		host  string
		now   time.Time
	}{
		{"untrusted", x509.NewCertPool(), "127.0.0.1", now},
		{"wrong hostname", trust, "mismatched.invalid", now},
		{"expired", trust, "127.0.0.1", certificate.NotAfter.Add(time.Second)},
		{"not yet valid", trust, "127.0.0.1", certificate.NotBefore.Add(-time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verifyConsoleTLS(ctx, address, test.host, test.roots, test.now); err == nil {
				t.Fatal("invalid console TLS accepted")
			}
		})
	}
	remaining, err = verifyConsoleTLS(ctx, address, "127.0.0.1", trust, certificate.NotAfter.Add(-29*24*time.Hour))
	if err != nil || remaining != 29*24*time.Hour {
		t.Fatal("near-expiry certificate lifetime lost", err)
	}
	select {
	case <-requests:
		t.Fatal("certificate probe sent an HTTP request")
	default:
	}
}

func TestDoctorTLSHandshakeHonorsTotalDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := verifyConsoleTLS(ctx, listener.Addr().String(), "console.example.com", nil, time.Now()); err == nil {
		t.Fatal("stalled TLS handshake succeeded")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("TLS handshake exceeded its context budget")
	}
	select {
	case connection := <-accepted:
		connection.Close()
	case <-time.After(time.Second):
		t.Fatal("TLS deadline fixture did not accept its connection")
	}
}
