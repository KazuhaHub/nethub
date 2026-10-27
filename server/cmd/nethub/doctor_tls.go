package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"
)

// verifyConsoleTLS sends no HTTP request or credentials. The caller supplies the
// initialized console identity; production always uses the system trust store.
func verifyConsoleTLS(ctx context.Context, address, hostname string, roots *x509.CertPool, now time.Time) (time.Duration, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostname, RootCAs: roots, Time: func() time.Time { return now }},
	}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return 0, errors.New("console TLS verification failed")
	}
	defer connection.Close()
	secured, ok := connection.(*tls.Conn)
	if !ok {
		return 0, errors.New("console TLS state unavailable")
	}
	state := secured.ConnectionState()
	if !state.HandshakeComplete || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return 0, errors.New("console TLS chain was not verified")
	}
	remaining := state.PeerCertificates[0].NotAfter.Sub(now)
	if remaining <= 0 {
		return 0, errors.New("console certificate expired")
	}
	return remaining, nil
}
