package relaycert

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func shortLeaf(t *testing.T, material Material, start, end time.Time) Material {
	t.Helper()
	leaf, err := certificate(material.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := certificate(material.CA)
	if err != nil {
		t.Fatal(err)
	}
	block, err := single(material.CAKey, "PRIVATE KEY")
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotBefore, leaf.NotAfter = start, end
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	material.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return material
}

func TestAssessRenewalDatesAndExpiredMaterial(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	m, err := Create("relay.example.test", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	short := shortLeaf(t, m, now.Add(-time.Hour), now.Add(5*time.Minute))
	a, err := Assess(short.CA, short.Certificate, short.Key, "relay.example.test", now)
	if err != nil || !a.Due || a.Expired || !a.CanExtend || a.AuthorityDue {
		t.Fatal("due short-lived leaf not recognized")
	}
	next, err := Renew(m.CA, m.CAKey, "relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	a, err = Assess(next.CA, next.Certificate, next.Key, "relay.example.test", now)
	if err != nil || a.Due || a.Expired || !a.RenewAt.Equal(a.ExpiresAt.Add(-30*24*time.Hour)) {
		t.Fatal("fresh renewal would loop or use wrong dates")
	}
	expired := shortLeaf(t, m, now.Add(-30*time.Minute), now.Add(-time.Second))
	a, err = Assess(expired.CA, expired.Certificate, expired.Key, "relay.example.test", now)
	if err != nil || !a.Expired || !a.Due || !a.CanExtend {
		t.Fatal("expired leaf cannot be assessed for recovery")
	}
	if Check(expired.CA, expired.Certificate, expired.Key, "relay.example.test", now) == nil {
		t.Fatal("historical assessment must not enable expired runtime material")
	}
	ca, _ := certificate(m.CA)
	clamped := shortLeaf(t, m, now, ca.NotAfter)
	a, err = Assess(clamped.CA, clamped.Certificate, clamped.Key, "relay.example.test", ca.NotAfter.Add(-time.Hour))
	if err != nil || !a.AuthorityDue || a.CanExtend || !a.Due {
		t.Fatal("authority clamp would cause repeated useless issuance")
	}
	a, err = Assess(clamped.CA, clamped.Certificate, clamped.Key, "relay.example.test", ca.NotAfter.Add(time.Second))
	if err != nil || !a.AuthorityExpired || !a.Expired || a.CanExtend {
		t.Fatal("expired authority hidden")
	}
	for _, host := range []string{"other.example.test", ""} {
		if _, err := Assess(m.CA, m.Certificate, m.Key, host, now); err != ErrMaterial {
			t.Fatal("unassigned identity accepted")
		}
	}
	if _, err := Assess(m.CA, m.Certificate, next.Key, "relay.example.test", now); err != ErrMaterial {
		t.Fatal("mixed generation accepted")
	}
	if _, err := Assess(m.CA, m.Certificate, m.Key, "relay.example.test", now.Add(-2*time.Hour)); err != ErrMaterial {
		t.Fatal("not-yet-valid leaf accepted")
	}
}

func TestFreshVerifiedObservation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	m, err := Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(m.Certificate, m.Key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	endpoint := netip.MustParseAddrPort(server.Listener.Addr().String())
	fingerprint, err := Observe(context.Background(), endpoint, "relay.example.test", m.CA)
	leaf, _ := certificate(m.Certificate)
	if err != nil || fingerprint != sha256.Sum256(leaf.Raw) {
		t.Fatal("served certificate was not verified and fingerprinted")
	}
	other, err := Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Observe(context.Background(), endpoint, "relay.example.test", other.CA); err != ErrObservation {
		t.Fatal("unknown authority accepted")
	}
	if _, err := Observe(context.Background(), endpoint, "other.example.test", m.CA); err != ErrObservation {
		t.Fatal("wrong hostname accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Observe(cancelled, endpoint, "relay.example.test", m.CA); err != ErrObservation {
		t.Fatal("cancelled observation ignored")
	}
	for _, bad := range []netip.AddrPort{{}, netip.MustParseAddrPort("0.0.0.0:7000"), netip.MustParseAddrPort("224.0.0.1:7000"), netip.MustParseAddrPort("127.0.0.1:0")} {
		if _, err := Observe(context.Background(), bad, "relay.example.test", m.CA); err != ErrObservation {
			t.Fatal("invalid observer endpoint accepted")
		}
	}
}

func TestObservationDeadlineDuringHandshake(t *testing.T) {
	m, err := Create("relay.example.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		<-stop
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Observe(ctx, netip.MustParseAddrPort(listener.Addr().String()), "relay.example.test", m.CA); err != ErrObservation {
		t.Fatal("stalled handshake did not fail with a fixed diagnostic")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("stalled handshake escaped the caller deadline")
	}
}
