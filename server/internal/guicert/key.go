package guicert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

var ErrKey = errors.New("invalid router certificate public key")

// PublicKey is the canonical P-256 SubjectPublicKeyInfo supplied at enrollment.
// Binding it requires the one-use admission transaction. Later requests must
// prove possession using a signed exact-assignment CSR, not a new bearer binding.
type PublicKey struct {
	DER         []byte `json:"-"`
	Fingerprint string `json:"fingerprint"`
}

func ValidatePublicKey(encoded string) (PublicKey, error) {
	if len(encoded) != 122 {
		return PublicKey{}, ErrKey
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(der) != 91 || base64.RawURLEncoding.EncodeToString(der) != encoded {
		return PublicKey{}, ErrKey
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) {
		return PublicKey{}, ErrKey
	}
	canonical, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(der, canonical) {
		return PublicKey{}, ErrKey
	}
	digest := sha256.Sum256(der)
	return PublicKey{DER: bytes.Clone(der), Fingerprint: hex.EncodeToString(digest[:])}, nil
}

// ValidateBoundCSR rejects an unbound/changed key before an issuer can submit a
// signed request. The caller must separately authorize a live device assignment.
func ValidateBoundCSR(encoded []byte, assignedHost, boundPublicKey string) (Request, error) {
	bound, err := ValidatePublicKey(boundPublicKey)
	if err != nil {
		return Request{}, ErrRequest
	}
	request, err := ValidateCSR(encoded, assignedHost)
	if err != nil || !bytes.Equal(request.PublicKey, bound.DER) {
		return Request{}, ErrRequest
	}
	return request, nil
}
