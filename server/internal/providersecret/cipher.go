// Package providersecret protects deployment-local provider credentials at rest.
package providersecret

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const MaxSecretBytes = 16 * 1024
const version byte = 1

type Purpose string

const (
	OIDCClientSecret Purpose = "oidc-client-secret"
	SAMLSigningKey   Purpose = "saml-signing-key"
)

// Binding authenticates the storage row and credential purpose without exposing
// them in the envelope. Callers supply the row's authoritative identifiers.
type Binding struct {
	TenantID, ProviderID string
	Purpose              Purpose
}

type Cipher struct{ aead cipher.AEAD }

var ErrUnavailable = errors.New("provider secret unavailable")

func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, ErrUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnavailable
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Cipher{aead: aead}, nil
}

func (*Cipher) String() string     { return "providersecret.Cipher(redacted)" }
func (c *Cipher) GoString() string { return c.String() }

func associatedData(b Binding) ([]byte, error) {
	if len(b.TenantID) < 1 || len(b.TenantID) > 64 || len(b.ProviderID) < 1 || len(b.ProviderID) > 64 ||
		b.Purpose != OIDCClientSecret && b.Purpose != SAMLSigningKey {
		return nil, ErrUnavailable
	}
	data := []byte("nethub/provider-secret/v1")
	for _, value := range []string{b.TenantID, b.ProviderID, string(b.Purpose)} {
		data = binary.BigEndian.AppendUint16(data, uint16(len(value)))
		data = append(data, value...)
	}
	return data, nil
}

// Seal uses the standard library's random 96-bit GCM nonce. The deployment key
// must be replaced before it has encrypted 2^32 messages across all processes.
func (c *Cipher) Seal(binding Binding, plaintext []byte) ([]byte, error) {
	if c == nil || c.aead == nil || len(plaintext) == 0 || len(plaintext) > MaxSecretBytes {
		return nil, ErrUnavailable
	}
	aad, err := associatedData(binding)
	if err != nil {
		return nil, err
	}
	return c.aead.Seal([]byte{version}, nil, plaintext, aad), nil
}

// Open refuses malformed, substituted and unauthenticated envelopes without
// returning partial plaintext or details about the failed credential.
func (c *Cipher) Open(binding Binding, envelope []byte) ([]byte, error) {
	if c == nil || c.aead == nil || len(envelope) < 1+c.aead.Overhead()+1 || len(envelope) > 1+c.aead.Overhead()+MaxSecretBytes || envelope[0] != version {
		return nil, ErrUnavailable
	}
	aad, err := associatedData(binding)
	if err != nil {
		return nil, err
	}
	plaintext, err := c.aead.Open(nil, nil, envelope[1:], aad)
	if err != nil {
		return nil, ErrUnavailable
	}
	return plaintext, nil
}
