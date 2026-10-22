package device

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/netip"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaycert"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

type publishedRepositoryFixture struct {
	*fakeRepository
	generation *relaytrust.Generation
	readErr    error
	reads      int
}

func (r *publishedRepositoryFixture) CurrentRelayTrust(ctx context.Context, _ string) (*relaytrust.Generation, error) {
	r.reads++
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, ErrUnavailable
	}
	if err := r.Health(ctx); err != nil {
		return nil, err
	}
	return r.generation, r.readErr
}

func publishedGenerationFixture(t *testing.T, name string, material relaycert.Material, now time.Time, number int) *relaytrust.Generation {
	t.Helper()
	bundle, err := relaytrust.Parse(string(material.CA), now)
	if err != nil {
		t.Fatal("current public fixture")
	}
	start, end := bundle.Window()
	raw, err := json.Marshal(map[string]any{"id": "33111111-1111-4111-8111-111111111111", "generation": number, "server_name": name, "ca_pem": bundle.PEM(), "bundle_fingerprint": bundle.Fingerprint(), "root_fingerprints": bundle.RootFingerprints(), "not_before": start, "valid_until": end, "published_at": now})
	if err != nil {
		t.Fatal(err)
	}
	g, err := relaytrust.DecodeGeneration(raw, name, now)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestPublishedTrustStartsWithExpiredBootstrapAndRefusesFallback(t *testing.T) {
	now := time.Now().UTC()
	relay := fixtureRelay(t)
	current, err := relaycert.Create(relay.ServerName, now)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := relaycert.Create(relay.ServerName, now.AddDate(-11, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relaytrust.Parse(string(expired.CA), now); err == nil {
		t.Fatal("bootstrap fixture is not actually expired")
	}
	relay.CAPEM = string(expired.CA)
	signer := fixtureService(t, &fakeRepository{}).signer
	r := &publishedRepositoryFixture{fakeRepository: &fakeRepository{publicTrust: string(current.CA)}, generation: publishedGenerationFixture(t, relay.ServerName, current, now, 1)}
	service, err := New(r, signer, relay)
	if err != nil || service.Health(context.Background()) != nil {
		t.Fatal("current published trust did not rescue stale-bootstrap startup", err)
	}
	response, err := service.Enroll(context.Background(), fixtureRequest(t), netip.MustParseAddr("192.0.2.1"))
	if err != nil || response.RelayCAPEM != r.publicTrust {
		t.Fatal("expired bootstrap replaced transaction-selected current trust", err)
	}
	// Even a currently valid bootstrap must not hide failure or downgrade of an
	// initialized publication. Nil is permitted only before initialization.
	validBootstrap := fixtureRelay(t)
	r.readErr = ErrUnavailable
	if _, err := New(r, signer, validBootstrap); err == nil || service.Health(context.Background()) == nil {
		t.Fatal("unavailable current publication fell back to bootstrap")
	}
	r.readErr, r.generation = nil, nil
	if service.Health(context.Background()) == nil {
		t.Fatal("initialized service downgraded to an empty head")
	}
	if _, err := New(r, signer, relay); err == nil {
		t.Fatal("uninitialized head accepted expired bootstrap")
	}
	if _, err := New(r, signer, validBootstrap); err != nil {
		t.Fatal("fresh valid bootstrap cannot initialize", err)
	}
}

func TestPublishedTrustRefreshesExpiredCacheAndPreservesTransactionSelection(t *testing.T) {
	r := &publishedRepositoryFixture{fakeRepository: &fakeRepository{}}
	service := fixtureService(t, r)
	now := time.Now().UTC()
	material, err := relaycert.Create(service.relay.ServerName, now)
	if err != nil {
		t.Fatal(err)
	}
	r.generation = publishedGenerationFixture(t, service.relay.ServerName, material, now, 1)
	r.publicTrust = string(material.CA)
	old, err := relaycert.Create(service.relay.ServerName, now.AddDate(-11, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(old.CA)
	oldRoot, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	service.certs = []*x509.Certificate{oldRoot}
	service.relay.CAPEM = string(old.CA)
	if service.trustValid(now) || service.Health(context.Background()) != nil {
		t.Fatal("current publication did not replace expired cached-root readiness")
	}
	newer, err := relaycert.Create(service.relay.ServerName, now)
	if err != nil {
		t.Fatal(err)
	}
	r.beforeIssue = func() { r.publicTrust = string(newer.CA) }
	response, err := service.Enroll(context.Background(), fixtureRequest(t), netip.MustParseAddr("192.0.2.1"))
	if err != nil || response.RelayCAPEM != string(newer.CA) || response.RelayCAPEM == r.generation.Bundle().PEM() {
		t.Fatal("response used preflight/cached trust instead of transaction snapshot", err)
	}
	r.beforeIssue = func() { r.publicTrust = "" }
	if response, err := service.Enroll(context.Background(), fixtureRequest(t), netip.MustParseAddr("192.0.2.1")); err == nil || response.DeviceSecret != "" {
		t.Fatal("initialized admission accepted an empty transaction trust snapshot")
	}
}

func TestPublishedTrustRejectsInvalidCurrentIdentityAndExpiry(t *testing.T) {
	now := time.Now().UTC()
	relay := fixtureRelay(t)
	signer := fixtureService(t, &fakeRepository{}).signer
	for _, name := range []string{relay.ServerName, "other.example.test"} {
		at := now
		if name == relay.ServerName {
			at = now.AddDate(-11, 0, 0)
		}
		material, err := relaycert.Create(name, at)
		if err != nil {
			t.Fatal(err)
		}
		r := &publishedRepositoryFixture{fakeRepository: &fakeRepository{}, generation: publishedGenerationFixture(t, name, material, at, 1)}
		if _, err := New(r, signer, relay); err == nil {
			t.Fatal("wrong-name or expired publication fell back to a valid bootstrap")
		}
	}
}

func TestPublishedTrustPreflightHonorsAdmissionLimits(t *testing.T) {
	r := &publishedRepositoryFixture{fakeRepository: &fakeRepository{}}
	service := fixtureService(t, r)
	before := r.reads
	input := fixtureRequest(t)
	ip := netip.MustParseAddr("192.0.2.1")
	service.workers <- struct{}{}
	service.workers <- struct{}{}
	if _, err := service.Enroll(context.Background(), input, ip); err != ErrBusy || r.reads != before || r.calls.Load() != 0 {
		t.Fatal("busy admission performed a public-trust database read")
	}
	<-service.workers
	<-service.workers
	service.windows[ip] = window{started: service.now(), count: 10}
	if _, err := service.Enroll(context.Background(), input, ip); err != ErrLimited || r.reads != before || r.calls.Load() != 0 {
		t.Fatal("rate-limited admission performed a public-trust database read")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Enroll(ctx, input, netip.MustParseAddr("192.0.2.2")); err != ErrUnavailable || r.reads != before {
		t.Fatal("cancelled admission performed a public-trust database read")
	}
}
