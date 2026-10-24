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
	if roots == nil {
		return Chain{}, ErrChain
	}
	result, certificates, err := inspectChain(encoded, csrPEM, assignedHost, now)
	if err != nil {
		return Chain{}, err
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	verified, err := certificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: assignedHost,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return Chain{}, ErrChain
	}
	for _, certificate := range verified[0] {
		if certificate.NotAfter.Before(result.ValidUntil) {
			result.ValidUntil = certificate.NotAfter
		}
	}
	return result, nil
}

// InspectChain checks public encoding, signatures between supplied certificates,
// validity and exact signed-request binding. It establishes NO trust anchor;
// clients must still use ValidateChain with independently configured roots.
func InspectChain(encoded, csrPEM []byte, assignedHost string, now time.Time) (Chain, error) {
	result, _, err := inspectChain(encoded, csrPEM, assignedHost, now)
	return result, err
}

func inspectChain(encoded, csrPEM []byte, assignedHost string, now time.Time) (Chain, []*x509.Certificate, error) {
	request, err := ValidateCSR(csrPEM, assignedHost)
	if err != nil || now.IsZero() || len(encoded) == 0 || len(encoded) > 32768 {
		return Chain{}, nil, ErrChain
	}
	var certificates []*x509.Certificate
	var canonical []byte
	rest := encoded
	seen := map[[32]byte]bool{}
	for len(bytes.Trim(rest, " \t\r\n\v\f")) != 0 {
		rest = bytes.TrimLeft(rest, " \t\r\n\v\f")
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(certificates) == 5 {
			return Chain{}, nil, ErrChain
		}
		encodedBlock := pem.EncodeToMemory(block)
		// Compare each consumed block so pem.Decode cannot skip malformed input.
		// Issuers may separate blocks with blank lines or use CRLF line endings.
		consumed := bytes.ReplaceAll(rest[:len(rest)-len(tail)], []byte("\r\n"), []byte("\n"))
		if !bytes.Equal(bytes.Trim(consumed, " \t\r\n\v\f"), bytes.TrimSpace(encodedBlock)) {
			return Chain{}, nil, ErrChain
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		digest := sha256.Sum256(block.Bytes)
		if err != nil || seen[digest] || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return Chain{}, nil, ErrChain
		}
		seen[digest] = true
		certificates = append(certificates, certificate)
		canonical = append(canonical, encodedBlock...)
		rest = tail
	}
	if len(certificates) == 0 {
		return Chain{}, nil, ErrChain
	}
	leaf := certificates[0]
	csr, _ := x509.ParseCertificateRequest(request.DER)
	if leaf.IsCA || !leaf.BasicConstraintsValid || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, request.PublicKey) ||
		len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != assignedHost || len(leaf.IPAddresses) != 0 ||
		len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 || leaf.Subject.CommonName != "" && leaf.Subject.CommonName != assignedHost {
		return Chain{}, nil, ErrChain
	}
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth
	}
	if !serverAuth || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return Chain{}, nil, ErrChain
	}
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(oidSAN) && !bytes.Equal(extension.Value, csr.Extensions[0].Value) {
			return Chain{}, nil, ErrChain
		}
	}
	until := leaf.NotAfter
	for i := 1; i < len(certificates); i++ {
		if certificates[i-1].CheckSignatureFrom(certificates[i]) != nil {
			return Chain{}, nil, ErrChain
		}
		if certificates[i].NotAfter.Before(until) {
			until = certificates[i].NotAfter
		}
	}
	return Chain{PEM: bytes.Clone(canonical), Fingerprint: sha256.Sum256(leaf.Raw),
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, ValidUntil: until}, certificates, nil
}
