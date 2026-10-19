package relaycert

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"time"
)

// Assessment describes validated public material, including an expired leaf.
// The signing key is neither needed nor returned. This does not establish that
// a running process has loaded the assessed generation.
type Assessment struct {
	Fingerprint      string    `json:"fingerprint"`
	ExpiresAt        time.Time `json:"expires_at"`
	RenewAt          time.Time `json:"renew_at"`
	AuthorityExpiry  time.Time `json:"authority_expiry"`
	Due              bool      `json:"due"`
	Expired          bool      `json:"expired"`
	AuthorityDue     bool      `json:"authority_due"`
	AuthorityExpired bool      `json:"authority_expired"`
	CanExtend        bool      `json:"can_extend"`
}

// Assess checks identity, key and chain at a valid historical instant when the
// leaf has expired. Expiry remains explicit; historical validation never grants
// current TLS trust or permission to restore an expired rollback generation.
func Assess(caPEM, certPEM, keyPEM []byte, name string, now time.Time) (Assessment, error) {
	ca, caErr := certificate(caPEM)
	leaf, leafErr := certificate(certPEM)
	if caErr != nil || leafErr != nil || now.IsZero() || now.Before(leaf.NotBefore) || !leaf.NotAfter.After(leaf.NotBefore) {
		return Assessment{}, ErrMaterial
	}
	verifiedAt := now
	expires := leaf.NotAfter
	if ca.NotAfter.Before(expires) {
		expires = ca.NotAfter
	}
	if !verifiedAt.Before(expires) {
		verifiedAt = expires.Add(-time.Nanosecond)
	}
	if err := Check(caPEM, certPEM, keyPEM, name, verifiedAt); err != nil {
		return Assessment{}, ErrMaterial
	}
	lead := 30 * 24 * time.Hour
	if lifetime := leaf.NotAfter.Sub(leaf.NotBefore) / 3; lifetime < lead {
		lead = lifetime
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	when := leaf.NotAfter.Add(-lead)
	return Assessment{Fingerprint: hex.EncodeToString(fingerprint[:]), ExpiresAt: leaf.NotAfter, RenewAt: when,
		AuthorityExpiry: ca.NotAfter, Due: !now.Before(when), Expired: !now.Before(leaf.NotAfter),
		AuthorityDue: !now.Before(ca.NotAfter.Add(-30 * 24 * time.Hour)), AuthorityExpired: !now.Before(ca.NotAfter),
		CanExtend: now.Before(ca.NotAfter) && leaf.NotAfter.Before(ca.NotAfter)}, nil
}

var ErrObservation = errors.New("relay TLS observation failed")

// Observe makes a fresh, direct, bounded TLS connection. It returns the served
// leaf fingerprint only after chain and hostname verification. Callers compare
// it with the intended generation before recording application success.
func Observe(ctx context.Context, endpoint netip.AddrPort, name string, caPEM []byte) ([32]byte, error) {
	if !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || !validName(name) {
		return [32]byte{}, ErrObservation
	}
	ca, err := certificate(caPEM)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.CheckSignatureFrom(ca) != nil {
		return [32]byte{}, ErrObservation
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: 5 * time.Second}
	raw, err := dialer.DialContext(bounded, "tcp", endpoint.String())
	if err != nil {
		return [32]byte{}, ErrObservation
	}
	defer raw.Close()
	connection := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12})
	if err := connection.HandshakeContext(bounded); err != nil {
		return [32]byte{}, ErrObservation
	}
	state := connection.ConnectionState()
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return [32]byte{}, ErrObservation
	}
	return sha256.Sum256(state.PeerCertificates[0].Raw), nil
}
