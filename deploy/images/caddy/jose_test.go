package main

import (
	"encoding/base64"
	"encoding/json"
	"runtime/debug"
	"strconv"
	"testing"

	"go.step.sm/crypto/jose"
)

func TestJOSERejectsOversizedRSAParameters(t *testing.T) {
	for _, bits := range []int{2048, 4096, 4097} {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			modulus := make([]byte, (bits+7)/8)
			modulus[0], modulus[len(modulus)-1] = byte(1<<((bits-1)%8)), 1
			input := `{"kty":"RSA","e":"AQAB","n":"` + base64.RawURLEncoding.EncodeToString(modulus) + `"}`
			var key jose.JSONWebKey
			err := json.Unmarshal([]byte(input), &key)
			if (err != nil) != (bits > 4096) {
				t.Fatal("RSA JWK bounds changed through the Smallstep compatibility API")
			}
		})
	}
}

func TestCaddyLinksOnlyPatchedJOSE(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("linked dependency metadata unavailable")
	}
	found := false
	for _, dependency := range info.Deps {
		if dependency.Path == "github.com/go-jose/go-jose/v3" {
			t.Fatal("legacy unpatched JOSE is linked into the standard Caddy bundle")
		}
		if dependency.Path == "github.com/go-jose/go-jose/v4" {
			if dependency.Version != "v4.1.6" || dependency.Replace != nil {
				t.Fatal("JOSE must use the checksum-pinned patched upstream release")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("patched JOSE missing from the actual linked dependency graph")
	}
}
