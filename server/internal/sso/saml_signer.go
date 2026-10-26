package sso

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

var ErrSAMLSigningIdentity = errors.New("SAML signing identity unavailable")

// NewSAMLSigningIdentity creates a provider-local signing identity. The returned
// private PEM bundle must be sealed before storage and must never enter an API.
// Its self-signed certificate identifies an SP key, not a public TLS endpoint.
func NewSAMLSigningIdentity(now time.Time) ([]byte, error) {
	if now.IsZero() {
		return nil, ErrSAMLSigningIdentity
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, ErrSAMLSigningIdentity
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, ErrSAMLSigningIdentity
	}
	serial.Add(serial, big.NewInt(1))
	certificate := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "NetHub SAML service provider"},
		NotBefore: now.UTC().Add(-5 * time.Minute), NotAfter: now.UTC().AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return nil, ErrSAMLSigningIdentity
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrSAMLSigningIdentity
	}
	defer clear(privateDER)
	bundle := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	return bundle, nil
}

// ParseSAMLSigningIdentity restores the bounded, encrypted provider-local bundle.
// Protocol signing and algorithm validation remain delegated to authcore.
func ParseSAMLSigningIdentity(bundle []byte) (crypto.Signer, *x509.Certificate, error) {
	if len(bundle) == 0 || len(bundle) > 16*1024 || !bytes.HasPrefix(bundle, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, nil, ErrSAMLSigningIdentity
	}
	private, remaining := pem.Decode(bundle)
	if private == nil || private.Type != "PRIVATE KEY" || len(private.Headers) != 0 || !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, nil, ErrSAMLSigningIdentity
	}
	defer clear(private.Bytes)
	certificate, remaining := pem.Decode(remaining)
	if certificate == nil || certificate.Type != "CERTIFICATE" || len(certificate.Headers) != 0 || len(bytes.TrimSpace(remaining)) != 0 {
		return nil, nil, ErrSAMLSigningIdentity
	}
	key, err := x509.ParsePKCS8PrivateKey(private.Bytes)
	if err != nil {
		return nil, nil, ErrSAMLSigningIdentity
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, ErrSAMLSigningIdentity
	}
	cert, err := x509.ParseCertificate(certificate.Bytes)
	if err != nil || !strongSAMLMetadataKey(cert) {
		return nil, nil, ErrSAMLSigningIdentity
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) {
		return nil, nil, ErrSAMLSigningIdentity
	}
	return signer, cert, nil
}
