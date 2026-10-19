package guicert

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

var ErrChain = errors.New("invalid router certificate chain")

// Chain contains public installation material only. It establishes neither
// current device authorization nor successful application on a router.
type Chain struct {
	PEM         []byte    `json:"-"`
	Fingerprint [32]byte  `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	ValidUntil  time.Time `json:"valid_until"`
}

// ValidateChain binds an issuer response to the device's signed exact-name CSR.
// Roots must come from independently configured trust, never from this response.
func ValidateChain(encoded, csrPEM []byte, assignedHost string, roots *x509.CertPool, now time.Time) (Chain, error) {
	request, err := ValidateCSR(csrPEM, assignedHost)
	if err != nil || roots == nil || now.IsZero() || len(encoded) == 0 || len(encoded) > 32768 {
		return Chain{}, ErrChain
	}
	var certificates []*x509.Certificate
	var canonical []byte
	rest := encoded
	seen := map[[32]byte]bool{}
	for len(bytes.TrimSpace(rest)) != 0 {
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(certificates) == 5 {
			return Chain{}, ErrChain
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		digest := sha256.Sum256(block.Bytes)
		if err != nil || seen[digest] || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return Chain{}, ErrChain
		}
		seen[digest] = true
		certificates = append(certificates, certificate)
		canonical = append(canonical, pem.EncodeToMemory(block)...)
		rest = tail
	}
	if len(certificates) == 0 || !bytes.Equal(bytes.TrimSpace(encoded), bytes.TrimSpace(canonical)) {
		return Chain{}, ErrChain
	}
	leaf := certificates[0]
	csr, _ := x509.ParseCertificateRequest(request.DER)
	if leaf.IsCA || !leaf.BasicConstraintsValid || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, request.PublicKey) ||
		len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != assignedHost || len(leaf.IPAddresses) != 0 ||
		len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 || leaf.Subject.CommonName != "" && leaf.Subject.CommonName != assignedHost {
		return Chain{}, ErrChain
	}
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth
	}
	if !serverAuth || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return Chain{}, ErrChain
	}
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(oidSAN) && !bytes.Equal(extension.Value, csr.Extensions[0].Value) {
			return Chain{}, ErrChain
		}
	}
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certificates); i++ {
		if certificates[i-1].CheckSignatureFrom(certificates[i]) != nil {
			return Chain{}, ErrChain
		}
		intermediates.AddCert(certificates[i])
	}
	verified, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: assignedHost,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return Chain{}, ErrChain
	}
	until := leaf.NotAfter
	for _, certificate := range verified[0] {
		if certificate.NotAfter.Before(until) {
			until = certificate.NotAfter
		}
	}
	return Chain{PEM: bytes.Clone(canonical), Fingerprint: sha256.Sum256(leaf.Raw),
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, ValidUntil: until}, nil
}
