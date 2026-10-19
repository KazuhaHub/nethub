// Package relaycert issues deployment-private relay certificates.
package relaycert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"regexp"
	"time"
)

var ErrMaterial = errors.New("invalid relay certificate material")
var dnsName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

type Material struct {
	CA, CAKey, Certificate, Key []byte `json:"-"`
}

func validName(name string) bool {
	_, ipError := netip.ParseAddr(name)
	return len(name) <= 253 && dnsName.MatchString(name) && ipError != nil
}

func serial() (*big.Int, error) {
	value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, ErrMaterial
	}
	return value.Add(value, big.NewInt(1)), nil
}

func privatePEM(key crypto.Signer) ([]byte, error) {
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrMaterial
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}), nil
}

// Create prepares a new authority; callers must back it up before deployment.
func Create(name string, now time.Time) (Material, error) {
	if !validName(name) || now.IsZero() {
		return Material{}, ErrMaterial
	}
	now = now.UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, ErrMaterial
	}
	number, err := serial()
	if err != nil {
		return Material{}, err
	}
	ca := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: "NetHub deployment CA"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), BasicConstraintsValid: true,
		IsCA: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{name}}
	encoded, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		return Material{}, ErrMaterial
	}
	caKey, err := privatePEM(key)
	if err != nil {
		return Material{}, err
	}
	return Renew(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), caKey, name, now)
}

// Renew keeps authority material unchanged and creates a fresh relay key/leaf.
// Scheduling, publication, process application and rollback belong to maintenance.
func Renew(caPEM, caKeyPEM []byte, name string, now time.Time) (Material, error) {
	if !validName(name) || now.IsZero() {
		return Material{}, ErrMaterial
	}
	ca, err := certificate(caPEM)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.CheckSignatureFrom(ca) != nil ||
		now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return Material{}, ErrMaterial
	}
	block, err := single(caKeyPEM, "PRIVATE KEY")
	if err != nil {
		return Material{}, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Material{}, ErrMaterial
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return Material{}, ErrMaterial
	}
	public, publicError := x509.MarshalPKIXPublicKey(signer.Public())
	expected, expectedError := x509.MarshalPKIXPublicKey(ca.PublicKey)
	if publicError != nil || expectedError != nil || !bytes.Equal(public, expected) {
		return Material{}, ErrMaterial
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, ErrMaterial
	}
	number, err := serial()
	if err != nil {
		return Material{}, err
	}
	now = now.UTC().Truncate(time.Second)
	expires := now.AddDate(1, 0, 0)
	if ca.NotAfter.Before(expires) {
		expires = ca.NotAfter
	}
	leaf := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: "NetHub relay"},
		DNSNames: []string{name}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	encoded, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), signer)
	if err != nil {
		return Material{}, ErrMaterial
	}
	keyPEM, err := privatePEM(key)
	if err != nil {
		return Material{}, err
	}
	material := Material{CA: bytes.Clone(caPEM), CAKey: bytes.Clone(caKeyPEM),
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), Key: keyPEM}
	if err := Check(material.CA, material.Certificate, material.Key, name, now); err != nil {
		return Material{}, err
	}
	return material, nil
}

func single(data []byte, kind string) (*pem.Block, error) {
	if len(data) == 0 || len(data) > 32768 {
		return nil, ErrMaterial
	}
	block, rest := pem.Decode(bytes.TrimSpace(data))
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
		!bytes.Equal(bytes.TrimSpace(data), bytes.TrimSpace(pem.EncodeToMemory(block))) {
		return nil, ErrMaterial
	}
	return block, nil
}

func certificate(data []byte) (*x509.Certificate, error) {
	block, err := single(data, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	value, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrMaterial
	}
	return value, nil
}

// Check needs only the public authority and runtime leaf/key, never the CA key.
func Check(caPEM, certPEM, keyPEM []byte, name string, now time.Time) error {
	if !validName(name) || now.IsZero() {
		return ErrMaterial
	}
	ca, err := certificate(caPEM)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.CheckSignatureFrom(ca) != nil {
		return ErrMaterial
	}
	leaf, err := certificate(certPEM)
	if err != nil || leaf.IsCA || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name || len(leaf.IPAddresses) != 0 ||
		len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 || !now.Before(leaf.NotAfter) {
		return ErrMaterial
	}
	if _, err := single(keyPEM, "PRIVATE KEY"); err != nil {
		return err
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return ErrMaterial
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return ErrMaterial
	}
	return nil
}
