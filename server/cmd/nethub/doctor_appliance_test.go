package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func TestPublishedApplianceRequiresSignedMatchingVersion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	entry := map[string]string{
		"name": "os-nethub-agent", "abi": "FreeBSD:15:amd64", "sha256": strings.Repeat("a", 64),
		"path": "repo/FreeBSD:15:amd64/All/os-nethub-agent-0.0.19.pkg", "frp_version": "0.71.1",
	}
	for _, tc := range []struct {
		name, relayVersion string
		entries            []map[string]string
		tamper             bool
		want               string
	}{
		{"match", "0.71.1", []map[string]string{entry}, false, "0.0.19"},
		{"mismatch", "0.72.0", []map[string]string{entry}, false, ""},
		{"duplicate", "0.71.1", []map[string]string{entry, entry}, false, ""},
		{"missing", "0.71.1", nil, false, ""},
		{"tampered", "0.71.1", []map[string]string{entry}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := json.Marshal(map[string]any{
				"schema_version": 2, "additional_packages": tc.entries,
			})
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(report)
			signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			if tc.tamper {
				report = append(report, '\n')
			}
			got, err := verifyPublishedAppliance(publicKey, report, signature, tc.relayVersion)
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("verifyPublishedAppliance = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}
