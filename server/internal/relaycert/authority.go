package relaycert

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// AuthorityIdentity verifies the exact single self-signed CA and matching key
// without issuing a leaf or requiring current validity. Expired issuer recovery
// must still identify the original backed-up authority before preparing a successor.
func AuthorityIdentity(caPEM, keyPEM []byte) (string, error) {
	ca, err := certificate(caPEM)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 ||
		!bytes.Equal(ca.RawSubject, ca.RawIssuer) || ca.CheckSignatureFrom(ca) != nil {
		return "", ErrMaterial
	}
	block, err := single(keyPEM, "PRIVATE KEY")
	if err != nil {
		return "", ErrMaterial
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", ErrMaterial
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return "", ErrMaterial
	}
	actual, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", ErrMaterial
	}
	expected, err := x509.MarshalPKIXPublicKey(ca.PublicKey)
	if err != nil || !bytes.Equal(actual, expected) {
		return "", ErrMaterial
	}
	digest := sha256.Sum256(ca.Raw)
	return hex.EncodeToString(digest[:]), nil
}
