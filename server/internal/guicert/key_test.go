package guicert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
)

func TestPublicKeyAndSignedRequestBinding(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	encoded := base64.RawURLEncoding.EncodeToString(der)
	bound, err := ValidatePublicKey(encoded)
	digest := sha256.Sum256(der)
	if err != nil || bound.Fingerprint != hex.EncodeToString(digest[:]) {
		t.Fatal("public binding")
	}
	const host = "a1b2c3d4.routers.example.test"
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, key)
	request := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	if _, err := ValidateBoundCSR(request, host, encoded); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", strings.Repeat("A", 122), encoded + "=", base64.StdEncoding.EncodeToString(der), encoded[:121] + "B"} {
		if _, err := ValidatePublicKey(invalid); err != ErrKey {
			t.Fatal("invalid public encoding accepted")
		}
		if _, err := ValidateBoundCSR(request, host, invalid); err != ErrRequest {
			t.Fatal("unbound request accepted")
		}
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if _, err := ValidateBoundCSR(request, host, base64.RawURLEncoding.EncodeToString(otherDER)); err != ErrRequest {
		t.Fatal("different key accepted")
	}
	if _, err := ValidateBoundCSR(request, "e5f6g7h8.routers.example.test", encoded); err != ErrRequest {
		t.Fatal("different assignment accepted")
	}
	invalidDER := append([]byte(nil), der...)
	for i := 27; i < len(invalidDER); i++ {
		invalidDER[i] = 0
	}
	if _, err := ValidatePublicKey(base64.RawURLEncoding.EncodeToString(invalidDER)); err != ErrKey {
		t.Fatal("invalid public point accepted")
	}
	bound.DER[0] ^= 1
	if _, err := ValidatePublicKey(encoded); err != nil {
		t.Fatal("returned material aliases input")
	}
}
