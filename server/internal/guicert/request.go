// Package guicert validates router certificate requests against an assigned name.
package guicert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net/netip"
	"regexp"
)

var ErrRequest = errors.New("invalid router certificate request")
var dnsName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
var oidCN = asn1.ObjectIdentifier{2, 5, 4, 3}

// Request contains public material only. It is intentionally excluded from JSON
// so ordinary job/status logging cannot expose raw submitted request content.
type Request struct {
	DER         []byte   `json:"-"`
	PublicKey   []byte   `json:"-"`
	Fingerprint [32]byte `json:"-"`
}

// ValidateCSR proves possession of a P-256 key and binds its sole requested SAN
// to assignedHost. The caller must authorize the current tenant/device/assignment
// in its own transaction; a valid CSR is not an enrollment or ownership grant.
func ValidateCSR(encoded []byte, assignedHost string) (Request, error) {
	_, ipError := netip.ParseAddr(assignedHost)
	if len(assignedHost) > 253 || !dnsName.MatchString(assignedHost) || ipError == nil || len(encoded) == 0 || len(encoded) > 8192 {
		return Request{}, ErrRequest
	}
	block, tail := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(tail)) != 0 || !bytes.Equal(bytes.TrimSpace(encoded), bytes.TrimSpace(pem.EncodeToMemory(block))) {
		return Request{}, ErrRequest
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.Version != 0 || csr.SignatureAlgorithm != x509.ECDSAWithSHA256 || csr.CheckSignature() != nil ||
		len(csr.DNSNames) != 1 || csr.DNSNames[0] != assignedHost || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		return Request{}, ErrRequest
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) {
		return Request{}, ErrRequest
	}
	for _, field := range csr.Subject.Names {
		if !field.Type.Equal(oidCN) || field.Value != assignedHost {
			return Request{}, ErrRequest
		}
	}
	if len(csr.Subject.Names) > 1 || len(csr.Extensions) != 1 || !csr.Extensions[0].Id.Equal(oidSAN) {
		return Request{}, ErrRequest
	}
	san, err := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte(assignedHost)}})
	if err != nil || !bytes.Equal(san, csr.Extensions[0].Value) {
		return Request{}, ErrRequest
	}
	return Request{DER: bytes.Clone(csr.Raw), PublicKey: bytes.Clone(csr.RawSubjectPublicKeyInfo), Fingerprint: sha256.Sum256(csr.Raw)}, nil
}
