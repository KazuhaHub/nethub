package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"go.step.sm/crypto/jose"
)

func TestJOSEMigrationRetainsAudienceAndCompactJWT(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, nil)
	if err != nil {
		t.Fatal("fixture signing key refused")
	}
	serialized, err := jose.Signed(signer).Claims(jose.Claims{Subject: "fixture", Audience: jose.Audience{"expected"}}).Serialize()
	if err != nil || strings.Count(serialized, ".") != 2 {
		t.Fatal("migrated JWT builder did not return compact serialization")
	}
	token, err := jose.ParseSigned(serialized)
	if err != nil {
		t.Fatal("compact JWT parse failed")
	}
	var claims jose.Claims
	if token.Claims(key, &claims) != nil || claims.Subject != "fixture" {
		t.Fatal("migrated JWT signature or payload verification failed")
	}
	if claims.Validate(jose.Expected{AnyAudience: jose.Audience{"expected"}}) != nil {
		t.Fatal("matching single audience refused")
	}
	if claims.Validate(jose.Expected{AnyAudience: jose.Audience{"different"}}) == nil {
		t.Fatal("wrong single audience accepted")
	}
}

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
