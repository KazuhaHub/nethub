package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/claim"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

type fakeRepository struct {
	calls       atomic.Int32
	record      Registration
	failure     error
	beforeIssue func()
}

func (r *fakeRepository) Health(context.Context) error { return r.failure }

func (r *fakeRepository) Register(_ context.Context, record Registration, issue func(Assignment) (string, error)) (Assignment, error) {
	r.calls.Add(1)
	if r.failure != nil {
		return Assignment{}, r.failure
	}
	if err := record.Validate(); err != nil {
		return Assignment{}, err
	}
	r.record = record
	if r.beforeIssue != nil {
		r.beforeIssue()
	}
	value := Assignment{ID: "11111111-1111-4111-8111-111111111111", TenantID: "22222222-2222-4222-8222-222222222222",
		OwnerID: "33333333-3333-4333-8333-333333333333", Subdomain: record.Candidates[0], IssuedAt: time.Now().UTC().Truncate(time.Microsecond)}
	var err error
	value.Claim, err = issue(value)
	return value, err
}

func fixtureRequest(t *testing.T) protocol.EnrollRequest {
	t.Helper()
	data, err := os.ReadFile("../../../proto/examples/valid/enroll-request.json")
	if err != nil {
		t.Fatal(err)
	}
	request, err := protocol.DecodeEnroll(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestEnrollmentCarriesInitialCertificateKeyBinding(t *testing.T) {
	data, err := os.ReadFile("../../../proto/examples/valid/enroll-bound-request.json")
	if err != nil {
		t.Fatal(err)
	}
	request, err := protocol.DecodeEnroll(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{}
	service := fixtureService(t, repository)
	response, err := service.Enroll(context.Background(), request, netip.MustParseAddr("192.0.2.1"))
	if err != nil || repository.record.GUIPublicKey != request.GUIPublicKey || len(response.GUIKeyFingerprint) != 64 {
		t.Fatalf("binding: %v", err)
	}
	var expected protocol.EnrollResponse
	encoded, _ := os.ReadFile("../../../proto/examples/valid/enroll-bound-response.json")
	if json.Unmarshal(encoded, &expected) != nil || response.GUIKeyFingerprint != expected.GUIKeyFingerprint {
		t.Fatal("binding acknowledgement")
	}
}

func fixtureRelay(t *testing.T) RelayConfig {
	t.Helper()
	data, err := os.ReadFile("../../../proto/examples/valid/enroll-response.json")
	var response protocol.EnrollResponse
	if err != nil || json.Unmarshal(data, &response) != nil {
		t.Fatal("relay fixture is unavailable")
	}
	return RelayConfig{Address: response.ServerAddr, ServerName: response.ServerName,
		Port: response.ServerPort, FRPToken: response.FRPToken, CAPEM: response.RelayCAPEM}
}

func fixtureService(t *testing.T, repository Repository) *Service {
	t.Helper()
	signer, err := claim.New("initial", map[string][]byte{"initial": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(repository, signer, fixtureRelay(t))
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestEnrollmentSeparatesOpaqueSecretsFromRegistration(t *testing.T) {
	repository := &fakeRepository{}
	service := fixtureService(t, repository)
	request := fixtureRequest(t)
	response, err := service.Enroll(context.Background(), request, netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(request.EnrollToken)
	if repository.calls.Load() != 1 || repository.record.TokenHash != sha256.Sum256(raw) {
		t.Fatal("repository did not receive the raw-token digest")
	}
	if match, err := auth.VerifyPassword(repository.record.SecretHash, response.DeviceSecret); err != nil || !match {
		t.Fatal("stored hash does not match the returned device secret")
	}
	encoded, _ := json.Marshal(repository.record)
	if bytes.Contains(encoded, []byte(request.EnrollToken)) || bytes.Contains(encoded, []byte(response.DeviceSecret)) || bytes.Contains(encoded, []byte(repository.record.SecretHash)) {
		t.Fatal("registration serialization contains credential material")
	}
	payload, err := service.signer.Verify(response.DomainClaim)
	if err != nil || payload.DeviceID != response.DeviceID || payload.Subdomain != response.Subdomain {
		t.Fatal("response claim does not bind its assigned device")
	}
	if len(response.DeviceSecret) != 43 || len(repository.record.Candidates) != 8 || response.RelayCAPEM != service.relay.CAPEM || response.AgentProtocolVersion != protocol.Version {
		t.Fatal("response lacks required registration material")
	}
	if repository.record.Platform != request.Platform || repository.record.SourceIP != netip.MustParseAddr("192.0.2.1") {
		t.Fatal("metadata or source IP drifted")
	}
}

func TestIncompatibleOrInvalidInputNeverReachesHashingOrRepository(t *testing.T) {
	for _, mutate := range []func(*protocol.EnrollRequest){
		func(r *protocol.EnrollRequest) { r.AgentProtocolVersion = "2.0.0" },
		func(r *protocol.EnrollRequest) { r.AgentProtocolVersion = "1.0" },
		func(r *protocol.EnrollRequest) { r.EnrollToken = "invalid" },
		func(r *protocol.EnrollRequest) { r.Hostname = "injected\nvalue" },
	} {
		repository := &fakeRepository{}
		service := fixtureService(t, repository)
		service.hash = func(string) (string, error) { t.Fatal("invalid input reached hashing"); return "", ErrUnavailable }
		request := fixtureRequest(t)
		mutate(&request)
		response, err := service.Enroll(context.Background(), request, netip.MustParseAddr("192.0.2.1"))
		if err == nil || response.DeviceSecret != "" || repository.calls.Load() != 0 {
			t.Fatal("invalid input reached token consumption or returned credentials")
		}
	}
}

func TestUnavailableDependenciesNeverReturnCredentials(t *testing.T) {
	for _, failure := range []error{ErrDenied, errors.New("private internal diagnostic")} {
		repository := &fakeRepository{failure: failure}
		service := fixtureService(t, repository)
		response, err := service.Enroll(context.Background(), fixtureRequest(t), netip.MustParseAddr("192.0.2.1"))
		if err == nil || response.DeviceSecret != "" || strings.Contains(err.Error(), "private internal") {
			t.Fatal("repository failure exposed input or partial credentials")
		}
		if errors.Is(failure, ErrDenied) && !errors.Is(err, ErrDenied) {
			t.Fatal("generic token denial changed")
		}
	}
	for _, fail := range []func(*Service){
		func(s *Service) { s.entropy = bytes.NewReader(nil) },
		func(s *Service) { s.hash = func(string) (string, error) { return "", io.ErrUnexpectedEOF } },
		func(s *Service) { s.certs[0].NotAfter = s.now().Add(-time.Second) },
	} {
		repository := &fakeRepository{}
		service := fixtureService(t, repository)
		fail(service)
		response, err := service.Enroll(context.Background(), fixtureRequest(t), netip.MustParseAddr("192.0.2.1"))
		if !errors.Is(err, ErrUnavailable) || response.DeviceSecret != "" || repository.calls.Load() != 0 {
			t.Fatal("preflight failure consumed a token")
		}
	}
}

func TestBoundedHashWorkersAndCanceledRequests(t *testing.T) {
	repository := &fakeRepository{}
	service := fixtureService(t, repository)
	service.workers <- struct{}{}
	service.workers <- struct{}{}
	if _, err := service.Enroll(context.Background(), fixtureRequest(t), netip.MustParseAddr("192.0.2.1")); !errors.Is(err, ErrBusy) {
		t.Fatal("full hash-worker budget did not fail promptly")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Enroll(ctx, fixtureRequest(t), netip.MustParseAddr("192.0.2.1")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("canceled request was admitted")
	}
	if repository.calls.Load() != 0 {
		t.Fatal("busy/canceled request reached repository")
	}
}

func TestTrustExpiryDuringRegistrationDoesNotReturnCredentials(t *testing.T) {
	repository := &fakeRepository{}
	service := fixtureService(t, repository)
	repository.beforeIssue = func() { service.certs[0].NotAfter = service.now().Add(-time.Second) }
	response, err := service.Enroll(context.Background(), fixtureRequest(t), netip.MustParseAddr("192.0.2.1"))
	if !errors.Is(err, ErrUnavailable) || response.DeviceSecret != "" {
		t.Fatal("trust expiration before signing returned credentials")
	}
}

func TestIPBudgetAndCapacityDoNotEvictLiveEntries(t *testing.T) {
	service := fixtureService(t, &fakeRepository{})
	now := service.now()
	ip := netip.MustParseAddr("192.0.2.1")
	for range 10 {
		if err := service.admit(ip, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.admit(netip.MustParseAddr("::ffff:192.0.2.1"), now); !errors.Is(err, ErrLimited) {
		t.Fatal("IPv4-mapped address bypassed the shared budget")
	}
	if err := service.admit(ip, now.Add(time.Minute)); err != nil {
		t.Fatal("expired budget did not recover")
	}
	service.windows = make(map[netip.Addr]window)
	for i := range 10000 {
		address := [16]byte{0x20, 0x01, 0x0d, 0xb8}
		address[14], address[15] = byte(i>>8), byte(i)
		service.windows[netip.AddrFrom16(address)] = window{started: now, count: 1}
	}
	service.sweepAfter = now.Add(time.Minute)
	if err := service.admit(netip.MustParseAddr("192.0.2.1"), now); !errors.Is(err, ErrLimited) || len(service.windows) != 10000 {
		t.Fatal("capacity pressure evicted live entries")
	}
}

func TestRelayTrustValidationAndCanonicalPEM(t *testing.T) {
	signer := fixtureService(t, &fakeRepository{}).signer
	for _, mutate := range []func(*RelayConfig){
		func(c *RelayConfig) { c.CAPEM = "" },
		func(c *RelayConfig) { c.CAPEM = "untrusted junk" + c.CAPEM },
		func(c *RelayConfig) { c.CAPEM = "-----BEGIN CERTIFICATE-----\ninvalid\n" + c.CAPEM },
		func(c *RelayConfig) { c.CAPEM += c.CAPEM + c.CAPEM },
		func(c *RelayConfig) { c.ServerName = "relay.example.com\nvalue" },
		func(c *RelayConfig) { c.Address = "fe80::1%interface" },
		func(c *RelayConfig) { c.Port = 0 },
		func(c *RelayConfig) { c.FRPToken = "not-a-deployment-token" },
	} {
		relay := fixtureRelay(t)
		mutate(&relay)
		if _, err := New(&fakeRepository{}, signer, relay); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid relay configuration accepted")
		}
	}
	relay := fixtureRelay(t)
	relay.CAPEM = "\n " + strings.ReplaceAll(relay.CAPEM, "\n", "\r\n") + "\n"
	service, err := New(&fakeRepository{}, signer, relay)
	if err != nil || service.relay.CAPEM != fixtureRelay(t).CAPEM {
		t.Fatal("public trust was not normalized to the response's PEM format")
	}
}

func TestSubdomainAllocationIsUniqueBoundedAndExcludesReservedNames(t *testing.T) {
	service := fixtureService(t, &fakeRepository{})
	values, err := randomCandidates(service.entropy)
	if err != nil || len(values) != 8 {
		t.Fatal("failed to generate bounded candidate set")
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !subdomain.MatchString(value) || reserved[value] || seen[value] {
			t.Fatal("invalid or repeated candidate")
		}
		seen[value] = true
	}
	if _, err := randomCandidates(bytes.NewReader(bytes.Repeat([]byte{255}, 1024))); !errors.Is(err, ErrUnavailable) {
		t.Fatal("pathological entropy stream was not bounded")
	}
}
