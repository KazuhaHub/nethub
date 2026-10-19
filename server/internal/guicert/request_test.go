package guicert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"net"
	"testing"
)

func makeCSR(t *testing.T, template *x509.CertificateRequest, curve elliptic.Curve) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestValidateRouterCSR(t *testing.T) {
	const host = "device.router.example.com"
	encoded := makeCSR(t, &x509.CertificateRequest{DNSNames: []string{host}, Subject: pkix.Name{CommonName: host}}, elliptic.P256())
	request, err := ValidateCSR(encoded, host)
	if err != nil || len(request.DER) == 0 || len(request.PublicKey) == 0 || request.Fingerprint == [32]byte{} {
		t.Fatal("valid signed device request rejected")
	}
	encoded[0] = 'x'
	csr, err := x509.ParseCertificateRequest(request.DER)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatal("validated output is not independent public CSR material")
	}
	logged, err := json.Marshal(request)
	if err != nil || string(logged) != "{}" {
		t.Fatal("raw request leaked into ordinary JSON")
	}
}

func TestRejectUnassignedAndUnsupportedRequests(t *testing.T) {
	const host = "device.router.example.com"
	for name, template := range map[string]*x509.CertificateRequest{
		"another device":  {DNSNames: []string{"other.router.example.com"}},
		"multiple names":  {DNSNames: []string{host, "other.router.example.com"}},
		"wildcard":        {DNSNames: []string{"*.router.example.com"}},
		"no SAN":          {},
		"IP SAN":          {DNSNames: []string{host}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}},
		"email SAN":       {DNSNames: []string{host}, EmailAddresses: []string{"operator@example.com"}},
		"foreign subject": {DNSNames: []string{host}, Subject: pkix.Name{CommonName: "other.router.example.com"}},
		"organization":    {DNSNames: []string{host}, Subject: pkix.Name{Organization: []string{"unapproved"}}},
		"requested CA":    {DNSNames: []string{host}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{48, 3, 1, 1, 255}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateCSR(makeCSR(t, template, elliptic.P256()), host); err != ErrRequest {
				t.Fatal("unapproved request accepted")
			}
		})
	}
	valid := makeCSR(t, &x509.CertificateRequest{DNSNames: []string{host}}, elliptic.P256())
	for _, name := range []string{"", "DEVICE.router.example.com", "*.router.example.com", "127.0.0.1", "device", "device.router.example.com/path"} {
		if _, err := ValidateCSR(valid, name); err != ErrRequest {
			t.Fatal("invalid assigned identity accepted")
		}
	}
	for _, value := range [][]byte{nil, append(append([]byte{}, valid...), valid...), append(append([]byte{}, valid...), []byte("unexpected")...), make([]byte, 8193), makeCSR(t, &x509.CertificateRequest{DNSNames: []string{host}}, elliptic.P384())} {
		if _, err := ValidateCSR(value, host); err != ErrRequest {
			t.Fatal("unsupported encoding or key accepted")
		}
	}
	block, _ := pem.Decode(valid)
	block.Bytes[len(block.Bytes)-1] ^= 1
	if _, err := ValidateCSR(pem.EncodeToMemory(block), host); err != ErrRequest {
		t.Fatal("request without valid proof of key possession accepted")
	}
}
