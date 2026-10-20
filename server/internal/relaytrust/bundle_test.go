package relaytrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func rootFixture(t *testing.T, number int64, now time.Time, change func(*x509.Certificate)) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(number), Subject: pkix.Name{CommonName: "Private trust fixture"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	if change != nil {
		change(certificate)
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCanonicalTrustBundleIdentityAndIndependentSnapshots(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old := rootFixture(t, 1, now, nil)
	next := rootFixture(t, 2, now, nil)
	b, err := Parse(old+next, now)
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := Parse(" \n"+strings.ReplaceAll(next+old, "\n", "\r\n")+" \n", now)
	if err != nil || b.PEM() != reversed.PEM() || b.Fingerprint() != reversed.Fingerprint() {
		t.Fatal("order/whitespace created a different trust identity", err)
	}
	digest := sha256.Sum256([]byte("nethub-relay-trust-v1:" + b.PEM()))
	if b.Fingerprint() != hex.EncodeToString(digest[:]) {
		t.Fatal("trust identity domain separation changed")
	}
	first, err := Parse(old, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint() == b.Fingerprint() {
		t.Fatal("additional trust did not change identity")
	}
	roots := b.RootFingerprints()
	roots[0] = "changed"
	if b.RootFingerprints()[0] == "changed" || len(b.RootFingerprints()) != 2 {
		t.Fatal("mutable root identities escaped")
	}
	certificates, err := b.Certificates()
	if err != nil {
		t.Fatal(err)
	}
	certificates[0].NotAfter = now.Add(-time.Second)
	certificates[0].Raw[0] ^= 1
	if !b.ValidAt(now) {
		t.Fatal("caller changed private validity snapshot")
	}
	if _, err := b.Certificates(); err != nil {
		t.Fatal("caller changed private DER snapshot")
	}
	if encoded, err := json.Marshal(b); err != nil || string(encoded) != "{}" {
		t.Fatal("ordinary JSON exposed trust metadata")
	}
}

func TestTrustBundleRejectsMalformedDuplicateAndUnusableAuthorities(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid := rootFixture(t, 1, now, nil)
	for _, value := range []string{"", "garbage" + valid, valid + "garbage", valid + valid, valid + rootFixture(t, 2, now, nil) + rootFixture(t, 3, now, nil),
		"-----BEGIN CERTIFICATE-----\ninvalid\n" + valid,
		strings.Replace(valid, "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nUnexpected: header\n", 1),
		strings.Repeat(" ", MaxBundleBytes) + valid} {
		if _, err := Parse(value, now); err != ErrBundle {
			t.Fatal("invalid trust encoding accepted")
		}
	}
	for _, change := range []func(*x509.Certificate){
		func(c *x509.Certificate) { c.IsCA = false },
		func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
		func(c *x509.Certificate) { c.NotBefore = now.Add(time.Hour) },
		func(c *x509.Certificate) { c.NotAfter = now },
		func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{5, 0}}}
		},
	} {
		value := rootFixture(t, 2, now, change)
		if _, err := Parse(value, now); err != ErrBundle {
			t.Fatal("unusable authority accepted")
		}
	}
	block, _ := pem.Decode([]byte(valid))
	block.Bytes[len(block.Bytes)-1] ^= 1
	if _, err := Parse(string(pem.EncodeToMemory(block)), now); err != ErrBundle {
		t.Fatal("invalid self-signature accepted")
	}
	if _, err := Parse(valid, time.Time{}); err != ErrBundle {
		t.Fatal("missing verification time accepted")
	}
}

func TestTrustWindowUsesAllRootsAndExclusiveExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old := rootFixture(t, 1, now, func(c *x509.Certificate) { c.NotAfter = now.Add(time.Hour) })
	next := rootFixture(t, 2, now, func(c *x509.Certificate) { c.NotBefore = now.Add(-time.Minute) })
	b, err := Parse(old+next, now)
	if err != nil {
		t.Fatal(err)
	}
	start, end := b.Window()
	if !start.Equal(now.Add(-time.Minute)) || !end.Equal(now.Add(time.Hour)) {
		t.Fatal("combined trust validity window differs")
	}
	if b.ValidAt(start.Add(-time.Nanosecond)) || !b.ValidAt(start) || b.ValidAt(end) || b.ValidAt(time.Time{}) {
		t.Fatal("trust validity boundary differs")
	}
}

func TestOwnKeySignatureWithDifferentIssuerIsNotSelfSignedRoot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Private trust fixture"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	parent := *certificate
	parent.Subject = pkix.Name{CommonName: "Other issuer"}
	der, err := x509.CreateCertificate(rand.Reader, certificate, &parent, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil || parsed.CheckSignatureFrom(parsed) != nil {
		t.Fatal("fixture did not retain own-key signature", err)
	}
	if _, err := Parse(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), now); err != ErrBundle {
		t.Fatal("non-self-issued authority accepted")
	}
}
