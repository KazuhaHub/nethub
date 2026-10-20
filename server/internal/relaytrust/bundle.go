// Package relaytrust validates public relay trust without signing authority.
package relaytrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"sort"
	"strings"
	"time"
)

var ErrBundle = errors.New("invalid public relay trust bundle")

const MaxBundleBytes = 32768
const fingerprintDomain = "nethub-relay-trust-v1:"

// Bundle is a validated snapshot of at most two self-signed authorities. Its
// canonical identity is independent of PEM whitespace and certificate order.
// It does not publish a generation or prove that a device has applied trust.
type Bundle struct {
	pem          string
	fingerprint  string
	roots        []string
	certificates []*x509.Certificate
	notBefore    time.Time
	validUntil   time.Time
}

func Parse(value string, now time.Time) (*Bundle, error) {
	if len(value) == 0 || len(value) > MaxBundleBytes || now.IsZero() {
		return nil, ErrBundle
	}
	byFingerprint := make(map[string]*x509.Certificate)
	rest := strings.TrimSpace(value)
	for rest != "" {
		if !strings.HasPrefix(rest, "-----BEGIN CERTIFICATE-----") || len(byFingerprint) >= 2 {
			return nil, ErrBundle
		}
		const endMarker = "-----END CERTIFICATE-----"
		end := strings.Index(rest, endMarker)
		if end < 0 {
			return nil, ErrBundle
		}
		chunk, remaining := rest[:end+len(endMarker)], rest[end+len(endMarker):]
		if strings.Count(chunk, "-----BEGIN ") != 1 {
			return nil, ErrBundle
		}
		block, tail := pem.Decode([]byte(chunk))
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || strings.TrimSpace(string(tail)) != "" {
			return nil, ErrBundle
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
			len(certificate.UnhandledCriticalExtensions) != 0 ||
			!bytes.Equal(certificate.RawIssuer, certificate.RawSubject) ||
			certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			certificate.CheckSignatureFrom(certificate) != nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return nil, ErrBundle
		}
		digest := sha256.Sum256(certificate.Raw)
		identity := hex.EncodeToString(digest[:])
		if _, duplicate := byFingerprint[identity]; duplicate {
			return nil, ErrBundle
		}
		byFingerprint[identity] = certificate
		rest = strings.TrimSpace(remaining)
	}
	if len(byFingerprint) == 0 {
		return nil, ErrBundle
	}
	b := &Bundle{}
	for identity := range byFingerprint {
		b.roots = append(b.roots, identity)
	}
	sort.Strings(b.roots)
	var canonical strings.Builder
	for _, identity := range b.roots {
		certificate := byFingerprint[identity]
		b.certificates = append(b.certificates, certificate)
		canonical.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
		if b.notBefore.IsZero() || certificate.NotBefore.After(b.notBefore) {
			b.notBefore = certificate.NotBefore
		}
		if b.validUntil.IsZero() || certificate.NotAfter.Before(b.validUntil) {
			b.validUntil = certificate.NotAfter
		}
	}
	if canonical.Len() > MaxBundleBytes {
		return nil, ErrBundle
	}
	b.pem = canonical.String()
	digest := sha256.Sum256([]byte(fingerprintDomain + b.pem))
	b.fingerprint = hex.EncodeToString(digest[:])
	return b, nil
}

func (b *Bundle) PEM() string                    { return b.pem }
func (b *Bundle) Fingerprint() string            { return b.fingerprint }
func (b *Bundle) RootFingerprints() []string     { return append([]string(nil), b.roots...) }
func (b *Bundle) Window() (time.Time, time.Time) { return b.notBefore, b.validUntil }
func (b *Bundle) ValidAt(now time.Time) bool {
	return !now.IsZero() && !now.Before(b.notBefore) && now.Before(b.validUntil)
}

// Certificates returns independent parsed copies for existing TLS consumers.
// Mutating those copies cannot change the bundle's identity or validity window.
func (b *Bundle) Certificates() ([]*x509.Certificate, error) {
	var result []*x509.Certificate
	for _, certificate := range b.certificates {
		copy, err := x509.ParseCertificate(append([]byte(nil), certificate.Raw...))
		if err != nil {
			return nil, ErrBundle
		}
		result = append(result, copy)
	}
	return result, nil
}
