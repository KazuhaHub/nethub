package guicert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

type chainFixture struct {
	now                 time.Time
	root, issuer, leaf  *x509.Certificate
	rootKey, issuerKey  *ecdsa.PrivateKey
	deviceKey           *ecdsa.PrivateKey
	csr, leafPEM, caPEM []byte
	roots               *x509.CertPool
}

const certificateHost = "device.router.example.com"

func certificateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signCertificate(t *testing.T, template, parent *x509.Certificate, key, signer *ecdsa.PrivateKey) (*x509.Certificate, []byte) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newChainFixture(t *testing.T) chainFixture {
	t.Helper()
	f := chainFixture{now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC), rootKey: certificateKey(t), issuerKey: certificateKey(t), deviceKey: certificateKey(t)}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	f.root, _ = signCertificate(t, root, root, f.rootKey, f.rootKey)
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture issuer"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(180 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 0, MaxPathLenZero: true}
	f.issuer, f.caPEM = signCertificate(t, issuer, f.root, f.issuerKey, f.rootKey)
	f.leaf = &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: certificateHost},
		DNSNames: []string{certificateHost}, NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	_, f.leafPEM = signCertificate(t, f.leaf, f.issuer, f.deviceKey, f.issuerKey)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{certificateHost}}, f.deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	f.csr = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.root)
	return f
}

func TestValidateIssuedRouterChain(t *testing.T) {
	f := newChainFixture(t)
	encoded := append(bytes.Clone(f.leafPEM), f.caPEM...)
	chain, err := ValidateChain(encoded, f.csr, certificateHost, f.roots, f.now)
	if err != nil || chain.Fingerprint == [32]byte{} || !chain.NotAfter.Equal(f.leaf.NotAfter) || !bytes.Equal(chain.PEM, encoded) {
		t.Fatal("issued chain did not match the retained device request")
	}
	encoded[0] = 'x'
	if chain.PEM[0] != '-' {
		t.Fatal("installation bytes alias the issuer response")
	}
	logged, err := json.Marshal(chain)
	if err != nil || bytes.Contains(logged, []byte("CERTIFICATE")) {
		t.Fatal("raw chain appeared in ordinary status JSON")
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw})
	if _, err := ValidateChain(append(bytes.Clone(chain.PEM), rootPEM...), f.csr, certificateHost, f.roots, f.now); err != nil {
		t.Fatal("explicitly trusted root in a complete response was rejected")
	}
}

func TestPublicChainInspectionDoesNotSupplyTrust(t *testing.T) {
	f := newChainFixture(t)
	encoded := append(bytes.Clone(f.leafPEM), f.caPEM...)
	inspected, err := InspectChain(encoded, f.csr, certificateHost, f.now)
	if err != nil || inspected.Fingerprint == [32]byte{} {
		t.Fatal("valid public chain inspection failed", err)
	}
	if _, err := ValidateChain(encoded, f.csr, certificateHost, x509.NewCertPool(), f.now); err == nil {
		t.Fatal("publicly supplied chain became its own trusted anchor")
	}
	if _, err := ValidateChain(encoded, f.csr, certificateHost, nil, f.now); err == nil {
		t.Fatal("missing independent roots accepted")
	}
	if _, err := InspectChain(encoded, f.csr, "wrong.router.example.com", f.now); err == nil {
		t.Fatal("inspection lost exact signed name binding")
	}
}

func TestIssuerExpiryBoundsRouterValidity(t *testing.T) {
	f := newChainFixture(t)
	f.issuer.NotAfter = f.now.Add(time.Hour)
	issuer, ca := signCertificate(t, f.issuer, f.root, f.issuerKey, f.rootKey)
	_, leaf := signCertificate(t, f.leaf, issuer, f.deviceKey, f.issuerKey)
	chain, err := ValidateChain(append(leaf, ca...), f.csr, certificateHost, f.roots, f.now)
	if err != nil || !chain.ValidUntil.Equal(f.issuer.NotAfter) || !chain.NotAfter.Equal(f.leaf.NotAfter) {
		t.Fatal("effective chain expiry was hidden by the later leaf expiry")
	}
	if _, err := ValidateChain(chain.PEM, f.csr, certificateHost, f.roots, f.issuer.NotAfter); err != ErrChain {
		t.Fatal("expired intermediate accepted while the leaf remained valid")
	}
}

func TestRejectCorruptRouterChain(t *testing.T) {
	f := newChainFixture(t)
	block, _ := pem.Decode(f.leafPEM)
	block.Bytes[len(block.Bytes)-1] ^= 1
	corrupt := pem.EncodeToMemory(block)
	if _, err := ValidateChain(append(corrupt, f.caPEM...), f.csr, certificateHost, f.roots, f.now); err != ErrChain {
		t.Fatal("corrupt certificate signature accepted")
	}
	block, _ = pem.Decode(f.leafPEM)
	block.Headers = map[string]string{"unapproved": "value"}
	if _, err := ValidateChain(append(pem.EncodeToMemory(block), f.caPEM...), f.csr, certificateHost, f.roots, f.now); err != ErrChain {
		t.Fatal("ambiguous PEM metadata accepted")
	}
}

func TestRejectUntrustedOrUnboundRouterChain(t *testing.T) {
	f := newChainFixture(t)
	valid := append(bytes.Clone(f.leafPEM), f.caPEM...)
	foreign := newChainFixture(t)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw})
	if _, err := ValidateChain(append(bytes.Clone(valid), rootPEM...), f.csr, certificateHost, foreign.roots, f.now); err != ErrChain {
		t.Fatal("response-supplied root became a trust anchor")
	}
	for _, roots := range []*x509.CertPool{nil, x509.NewCertPool()} {
		if _, err := ValidateChain(valid, f.csr, certificateHost, roots, f.now); err != ErrChain {
			t.Fatal("missing independent trust accepted")
		}
	}
	for _, csr := range [][]byte{nil, foreign.csr, append(bytes.Clone(f.csr), f.csr...)} {
		if _, err := ValidateChain(valid, csr, certificateHost, f.roots, f.now); err != ErrChain {
			t.Fatal("chain detached from its signed device key request")
		}
	}
	for _, instant := range []time.Time{{}, f.now.Add(-2 * time.Minute), f.leaf.NotAfter} {
		if _, err := ValidateChain(valid, f.csr, certificateHost, f.roots, instant); err != ErrChain {
			t.Fatal("certificate outside its current validity accepted")
		}
	}
	if _, err := ValidateChain(valid, f.csr, "another.router.example.com", f.roots, f.now); err != ErrChain {
		t.Fatal("another assigned hostname accepted")
	}
	for _, response := range [][]byte{nil, f.leafPEM, append(bytes.Clone(f.caPEM), f.leafPEM...),
		append(bytes.Clone(valid), f.caPEM...), append(bytes.Clone(valid), foreign.caPEM...),
		append([]byte("garbage\n"), valid...), append(bytes.Clone(valid), []byte("trailer")...), make([]byte, 32769),
		append(bytes.Clone(valid), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("unwanted")})...)} {
		if _, err := ValidateChain(response, f.csr, certificateHost, f.roots, f.now); err != ErrChain {
			t.Fatal("incomplete, reordered, duplicate or mixed response accepted")
		}
	}
}

func TestRejectIssuedIdentityAndUsageExpansion(t *testing.T) {
	for name, alter := range map[string]func(*x509.Certificate){
		"another name": func(c *x509.Certificate) { c.DNSNames = []string{"another.router.example.com"} },
		"extra name":   func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "another.router.example.com") },
		"wildcard":     func(c *x509.Certificate) { c.DNSNames = []string{"*.router.example.com"} },
		"foreign CN":   func(c *x509.Certificate) { c.Subject.CommonName = "another.router.example.com" },
		"CA leaf":      func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign },
		"missing server purpose": func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		},
		"missing signing usage": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
		"hidden SAN identity": func(c *x509.Certificate) {
			value, _ := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte(certificateHost)}, {Class: 2, Tag: 6, Bytes: []byte("https://unapproved.example.com")}})
			c.ExtraExtensions = []pkix.Extension{{Id: oidSAN, Value: value}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newChainFixture(t)
			alter(f.leaf)
			_, leaf := signCertificate(t, f.leaf, f.issuer, f.deviceKey, f.issuerKey)
			if _, err := ValidateChain(append(leaf, f.caPEM...), f.csr, certificateHost, f.roots, f.now); err != ErrChain {
				t.Fatal("issuer expanded the authorized device certificate profile")
			}
		})
	}
}
