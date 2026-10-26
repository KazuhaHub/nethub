package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestDisposableOriginsAndExplicitUnverifiedClaim(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "fixture")
	now := time.Now()
	if err := prepare(directory, now); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	originalCredentials := read("credentials.json")
	var secrets credentials
	if err := json.Unmarshal(originalCredentials, &secrets); err != nil {
		t.Fatal(err)
	}
	if len(secrets.Password) != 64 || len(secrets.Clients) != 2 || secrets.Clients["one"] == secrets.Clients["two"] {
		t.Fatal("fixture credentials are not independent")
	}
	var dex struct {
		Issuer    string `json:"issuer"`
		Passwords []struct {
			Email, Hash string
			Verified    *bool `json:"emailVerified"`
		} `json:"staticPasswords"`
	}
	if err := json.Unmarshal(read("dex-one.json"), &dex); err != nil || dex.Issuer != "https://dex-one.test" {
		t.Fatal("unexpected issuer")
	}
	foundFalse := false
	for _, user := range dex.Passwords {
		if err := bcrypt.CompareHashAndPassword([]byte(user.Hash), []byte(secrets.Password)); err != nil {
			t.Fatal("Dex cannot verify its generated password")
		}
		if user.Email == "unverified@example.com" {
			foundFalse = user.Verified != nil && !*user.Verified
		}
	}
	if !foundFalse {
		t.Fatal("unverified must be explicit false, not Dex's true default")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(read("root.crt")) {
		t.Fatal("invalid fixture CA")
	}
	pair, err := tls.X509KeyPair(read("origin.crt"), read("origin.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"console.example.com", "dex-one.test", "dex-two.test"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host, CurrentTime: now}); err != nil {
			t.Fatal("fixture chain/hostname verification failed", host, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "wrong.test", CurrentTime: now}); err == nil {
		t.Fatal("fixture accepted another hostname")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "dex-one.test", CurrentTime: now.Add(3 * time.Hour)}); err == nil {
		t.Fatal("fixture accepted its expired leaf")
	}
	block, _ := pem.Decode(read("root.crt"))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("fixture root is not a public certificate")
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{"credentials.json", "origin.key", "dex-one.json", "dex-two.json"} {
			info, err := os.Stat(filepath.Join(directory, name))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("fixture secret permissions are not 0600", name)
			}
		}
	}
	if err := prepare(directory, now); err == nil {
		t.Fatal("fixture overwrote an existing directory")
	}
	if !bytes.Equal(read("credentials.json"), originalCredentials) {
		t.Fatal("refusal modified an earlier fixture")
	}
}
