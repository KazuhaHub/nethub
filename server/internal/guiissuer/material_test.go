package guiissuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func materialFixture(t *testing.T) (Snapshot, Progress, []byte, *x509.CertPool, func(string) bool, time.Time) {
	t.Helper()
	work, account, order, now := progressFixture(t)
	now = now.Truncate(time.Second)
	csrBlock, _ := pem.Decode(work.CSR)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Private fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{work.Host}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, csr.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	order.Status = "valid"
	order.CertificateURL = "https://acme.example.test/certificate/original"
	return work, Progress{Phase: "finalizing", Order: &order}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), roots, account.AllowsURL, now
}

func TestIssuedMaterialRequiresIndependentTrustOriginalKeyAndDurableIdentity(t *testing.T) {
	work, progress, chain, roots, allows, now := materialFixture(t)
	material, err := PrepareMaterial(work, progress, chain, roots, allows, now)
	if err != nil || len(material.PEM) == 0 || len(material.Fingerprint) != 64 || !material.RenewAfter.After(now) || !material.RenewAfter.Before(material.ValidUntil) {
		t.Fatal("valid original-key public material rejected", err)
	}
	if encoded, _ := json.Marshal(material); string(encoded) != "{}" {
		t.Fatal("public installation payload entered ordinary status JSON")
	}
	if _, err := PrepareMaterial(work, progress, chain, x509.NewCertPool(), allows, now); err == nil {
		t.Fatal("untrusted chain accepted")
	}
	bad := work
	bad.PublicKey = strings.Repeat("A", 122)
	if _, err := PrepareMaterial(bad, progress, chain, roots, allows, now); err == nil {
		t.Fatal("changed enrollment key accepted")
	}
	bad = work
	bad.CSRFingerprint = strings.Repeat("0", 64)
	if _, err := PrepareMaterial(bad, progress, chain, roots, allows, now); err == nil {
		t.Fatal("changed original CSR accepted")
	}
	before := progress
	before.Phase = "order_saved"
	if _, err := PrepareMaterial(work, before, chain, roots, allows, now); err == nil {
		t.Fatal("material completed without finalizing intent")
	}
	if _, err := PrepareMaterial(work, progress, append(chain, []byte("trailing")...), roots, allows, now); err == nil {
		t.Fatal("malformed returned material accepted")
	}
}

func TestRenewalSchedulingUsesLifetimeAndStableDeviceSpread(t *testing.T) {
	const device = "12345678-1234-1234-1234-123456789abc"
	start := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	for _, lifetime := range []time.Duration{5 * time.Minute, 24 * time.Hour, 90 * 24 * time.Hour, 365 * 24 * time.Hour} {
		end := start.Add(lifetime)
		next, err := RenewalTime(device, start, end, start)
		if err != nil || !next.After(start) || !next.Before(end) {
			t.Fatal("renewal schedule outside lifetime", err)
		}
		again, err := RenewalTime(device, start, end, start)
		if err != nil || next != again {
			t.Fatal("unchanged certificate changed its renewal bucket")
		}
		other, err := RenewalTime("23456789-2345-2345-2345-23456789abcd", start, end, start)
		if err != nil || next == other {
			t.Fatal("device buckets did not spread renewals")
		}
	}
	if _, err := RenewalTime(device, start, start.Add(5*time.Minute), start.Add(290*time.Second)); err == nil {
		t.Fatal("near-expired issuance could cause an immediate renewal loop")
	}
}
