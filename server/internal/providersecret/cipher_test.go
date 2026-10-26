package providersecret

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func fixtureCipher(t *testing.T) (*Cipher, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}
func fixtureBinding() Binding {
	return Binding{TenantID: "tenant-a", ProviderID: "provider-a", Purpose: OIDCClientSecret}
}

func TestProviderCredentialAndFlowPurposeIsolation(t *testing.T) {
	c, _ := fixtureCipher(t)
	for _, purpose := range []Purpose{OIDCClientSecret, SAMLSigningKey, OIDCFlowState, SAMLFlowState} {
		binding := Binding{TenantID: "tenant-a", ProviderID: "row-a", Purpose: purpose}
		sealed, err := c.Seal(binding, []byte("isolated protocol state"))
		if err != nil {
			t.Fatal(err)
		}
		for _, other := range []Purpose{OIDCClientSecret, SAMLSigningKey, OIDCFlowState, SAMLFlowState} {
			binding.Purpose = other
			opened, err := c.Open(binding, sealed)
			if other == purpose {
				if err != nil || string(opened) != "isolated protocol state" {
					t.Fatal("same-purpose state did not restore", err)
				}
			} else if !errors.Is(err, ErrUnavailable) || opened != nil {
				t.Fatal("credential or flow crossed its protocol purpose")
			}
		}
	}
}

func TestEnvelopeRandomizationBindingAndTamper(t *testing.T) {
	c, key := fixtureCipher(t)
	plaintext := []byte("isolated provider credential fixture")
	binding := fixtureBinding()
	seen := map[string]bool{}
	for range 128 {
		encrypted, err := c.Seal(binding, plaintext)
		if err != nil || bytes.Contains(encrypted, plaintext) || seen[string(encrypted)] {
			t.Fatal("credential encryption did not randomize and conceal its input", err)
		}
		seen[string(encrypted)] = true
		decoded, err := c.Open(binding, encrypted)
		if err != nil || !bytes.Equal(decoded, plaintext) {
			t.Fatal("credential did not round-trip", err)
		}
	}
	encrypted, err := c.Seal(binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	for i := range encrypted {
		changed := bytes.Clone(encrypted)
		changed[i] ^= 1
		result, err := c.Open(binding, changed)
		if !errors.Is(err, ErrUnavailable) || result != nil {
			t.Fatal("tampered credential returned plaintext", i)
		}
	}
	for _, wrong := range []Binding{{TenantID: "tenant-b", ProviderID: binding.ProviderID, Purpose: binding.Purpose}, {TenantID: binding.TenantID, ProviderID: "provider-b", Purpose: binding.Purpose}, {TenantID: binding.TenantID, ProviderID: binding.ProviderID, Purpose: SAMLSigningKey}} {
		if result, err := c.Open(wrong, encrypted); !errors.Is(err, ErrUnavailable) || result != nil {
			t.Fatal("credential moved across its binding")
		}
	}
	other, _ := fixtureCipher(t)
	if result, err := other.Open(binding, encrypted); !errors.Is(err, ErrUnavailable) || result != nil {
		t.Fatal("wrong deployment key returned plaintext")
	}
	// The cipher owns expanded key material, not the caller's mutable byte slice.
	clear(key)
	if result, err := c.Open(binding, encrypted); err != nil || !bytes.Equal(result, plaintext) {
		t.Fatal("caller key cleanup broke existing ciphertext", err)
	}
	one := Binding{TenantID: "a", ProviderID: "bc", Purpose: OIDCClientSecret}
	two := Binding{TenantID: "ab", ProviderID: "c", Purpose: OIDCClientSecret}
	encrypted, err = c.Seal(one, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := c.Open(two, encrypted); !errors.Is(err, ErrUnavailable) || result != nil {
		t.Fatal("ambiguous context concatenation accepted")
	}
	t.Log("Provider envelopes verified randomized AES-256-GCM, every-byte tamper refusal, wrong-key rejection and tenant/provider/purpose isolation")
}

func TestEnvelopeBoundsAndSafeDiagnostics(t *testing.T) {
	c, _ := fixtureCipher(t)
	binding := fixtureBinding()
	for _, size := range []int{0, 16, 24, 31, 33, 64} {
		if value, err := New(make([]byte, size)); !errors.Is(err, ErrUnavailable) || value != nil {
			t.Fatal("non-256-bit key accepted", size)
		}
	}
	for _, plain := range [][]byte{nil, {}, make([]byte, MaxSecretBytes+1)} {
		if result, err := c.Seal(binding, plain); !errors.Is(err, ErrUnavailable) || result != nil {
			t.Fatal("invalid plaintext size accepted")
		}
	}
	largest := bytes.Repeat([]byte{0xfe}, MaxSecretBytes)
	encrypted, err := c.Seal(binding, largest)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := c.Open(binding, encrypted); err != nil || !bytes.Equal(decoded, largest) {
		t.Fatal("largest credential failed", err)
	}
	for _, envelope := range [][]byte{nil, {}, []byte("unversioned plaintext"), encrypted[:len(encrypted)-1], append(bytes.Clone(encrypted), 0), make([]byte, MaxSecretBytes+100)} {
		if result, err := c.Open(binding, envelope); !errors.Is(err, ErrUnavailable) || result != nil {
			t.Fatal("invalid envelope accepted")
		}
	}
	for _, binding := range []Binding{{}, {TenantID: "a", ProviderID: "b", Purpose: "unknown"}, {TenantID: strings.Repeat("a", 65), ProviderID: "b", Purpose: OIDCClientSecret}} {
		if result, err := c.Seal(binding, []byte("fixture")); !errors.Is(err, ErrUnavailable) || result != nil {
			t.Fatal("invalid binding accepted")
		}
	}
	for _, empty := range []*Cipher{nil, {}} {
		if result, err := empty.Seal(binding, []byte("fixture")); !errors.Is(err, ErrUnavailable) || result != nil {
			t.Fatal("unconfigured cipher accepted encryption")
		}
		if result, err := empty.Open(binding, encrypted); !errors.Is(err, ErrUnavailable) || result != nil {
			t.Fatal("unconfigured cipher accepted decryption")
		}
	}
	encoded, err := json.Marshal(c)
	if err != nil || string(encoded) != "{}" || fmt.Sprint(c) != "providersecret.Cipher(redacted)" || fmt.Sprintf("%#v", c) != "providersecret.Cipher(redacted)" {
		t.Fatal("cipher diagnostics expose internal material")
	}
}

func TestEnvelopeConcurrentUse(t *testing.T) {
	c, _ := fixtureCipher(t)
	binding := fixtureBinding()
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			plaintext := []byte("concurrent credential fixture")
			encrypted, err := c.Seal(binding, plaintext)
			if err != nil {
				t.Error(err)
				return
			}
			result, err := c.Open(binding, encrypted)
			if err != nil || !bytes.Equal(result, plaintext) {
				t.Error("concurrent credential round-trip failed", err)
			}
		})
	}
	wg.Wait()
}
