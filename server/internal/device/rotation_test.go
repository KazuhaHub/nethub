package device

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

type rotationRepository struct {
	lifecycleRepository
	record  RotationRecord
	result  Assignment
	rotates int
	failure error
}

func (f *rotationRepository) RotateDevice(_ context.Context, c Credential, record RotationRecord, issue func(Assignment) (string, error)) (Assignment, error) {
	f.rotates++
	if f.failure != nil {
		return Assignment{}, f.failure
	}
	if record.Validate() != nil || c.Hash != f.credential.Hash {
		return Assignment{}, ErrDenied
	}
	if f.record.OperationID != "" {
		if record.OperationID != f.record.OperationID || !record.CandidateIsCurrent || record.CandidateDigest != f.record.CandidateDigest {
			return Assignment{}, ErrDenied
		}
		return f.result, nil
	}
	if record.CandidateIsCurrent {
		return Assignment{}, ErrDenied
	}
	f.result = Assignment{ID: record.DeviceID, TenantID: c.TenantID, Subdomain: "test1234", IssuedAt: time.Now().UTC().Truncate(time.Microsecond)}
	var err error
	f.result.Claim, err = issue(f.result)
	if err != nil {
		return Assignment{}, err
	}
	f.record = record
	f.credential.Hash = record.SecretHash
	return f.result, nil
}

func rotationFixture(t *testing.T) (*Service, *rotationRepository, protocol.RotateRequest, string) {
	t.Helper()
	old := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{61}, 32))
	hash, err := auth.HashPassword(old)
	if err != nil {
		t.Fatal(err)
	}
	repository := &rotationRepository{lifecycleRepository: lifecycleRepository{credential: Credential{
		TenantID: "22222222-2222-4222-8222-222222222222", Hash: hash}}}
	request := protocol.RotateRequest{Identity: protocol.Identity{AgentProtocolVersion: protocol.Version,
		DeviceID: "11111111-1111-4111-8111-111111111111"}, OperationID: "33333333-3333-4333-8333-333333333333",
		ReplacementSecret: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{62}, 32))}
	service := fixtureService(t, repository)
	request.ExpectedRelayCASHA256 = protocol.RelayTrustDigest(service.relay.CAPEM)
	return service, repository, request, old
}

func TestRotationHTTPAdmissionAndLostResponseRecovery(t *testing.T) {
	service, repository, input, old := rotationFixture(t)
	var log bytes.Buffer
	handler := testHTTP(t, service, &log)
	post := func(secret string, duplicate bool) *httptest.ResponseRecorder {
		data, _ := json.Marshal(input)
		r := requestHTTP(string(data))
		r.URL.Path = "/api/v1/devices/rotate"
		r.Header.Set("Authorization", "Bearer "+secret)
		if duplicate {
			r.Header.Add("Authorization", "Bearer "+secret)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, bearer := range []string{"", strings.Repeat("A", 43)} {
		if post(bearer, false).Code != 401 {
			t.Fatal("unauthenticated rotation admitted")
		}
	}
	if post(old, true).Code != 401 || repository.rotates != 0 {
		t.Fatal("duplicate bearer reached rotation")
	}
	first := post(old, false)
	var response protocol.RotateResponse
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &response) != nil || response.DeviceID != input.DeviceID ||
		response.OperationID != input.OperationID || response.DeviceSecret != input.ReplacementSecret || response.DomainClaim == "" ||
		first.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("rotation acknowledgement lost the candidate binding")
	}
	if repository.record.SecretHash == input.ReplacementSecret {
		t.Fatal("repository received plaintext instead of a password hash")
	}
	if ok, err := auth.VerifyPassword(repository.record.SecretHash, input.ReplacementSecret); err != nil || !ok {
		t.Fatal("replacement hash does not authenticate the candidate")
	}
	if w := post(old, false); w.Code != 401 || strings.Contains(w.Body.String(), old) || strings.Contains(w.Body.String(), input.ReplacementSecret) {
		t.Fatal("old credential remained valid or failure disclosed credentials")
	}
	// A committed candidate retries without spending another replacement hash.
	service.hash = func(string) (string, error) {
		t.Fatal("recovery rehashed a committed candidate")
		return "", ErrUnavailable
	}
	recovered := post(input.ReplacementSecret, false)
	if recovered.Code != 200 || recovered.Body.String() != first.Body.String() || strings.Contains(log.String(), input.ReplacementSecret) || strings.Contains(log.String(), old) {
		t.Fatal("lost-response retry changed assignment or disclosed credentials")
	}
}

func TestRotationRefusesOldProtocolBusyAndFailedHash(t *testing.T) {
	service, repository, request, old := rotationFixture(t)
	ip := netip.MustParseAddr("192.0.2.21")
	request.AgentProtocolVersion = "1.5.0"
	if _, err := service.Rotate(context.Background(), request, old, ip); !errors.Is(err, protocol.ErrRotationVersion) || repository.lookups.Load() != 0 {
		t.Fatal("old peer reached credential authentication")
	}
	request.AgentProtocolVersion = protocol.Version
	service.workers <- struct{}{}
	service.workers <- struct{}{}
	if _, err := service.Rotate(context.Background(), request, old, ip); !errors.Is(err, ErrBusy) || repository.lookups.Load() != 0 {
		t.Fatal("rotation bypassed shared hash-worker admission")
	}
	<-service.workers
	<-service.workers
	service.hash = func(string) (string, error) { return "", errors.New("private hashing diagnostic") }
	if _, err := service.Rotate(context.Background(), request, old, ip); !errors.Is(err, ErrUnavailable) || repository.rotates != 0 {
		t.Fatal("failed hash reached persistence")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Rotate(ctx, request, old, ip); !errors.Is(err, ErrUnavailable) || repository.rotates != 0 {
		t.Fatal("cancelled request mutated state")
	}
}

func TestRotationTrustConflictProjectionRetainsNoRemoteOrCredentialFields(t *testing.T) {
	service, repository, request, old := rotationFixture(t)
	repository.failure = ErrRotationTrustChanged
	var log bytes.Buffer
	handler, err := NewHTTP(HTTPConfig{Origin: "https://console.example.com", Logger: slog.New(slog.NewJSONHandler(&log, nil))}, service)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(request)
	r := httptest.NewRequest("POST", "https://console.example.com/api/v1/devices/rotate", bytes.NewReader(data))
	r.RemoteAddr = "192.0.2.29:12345"
	r.Header.Set("Authorization", "Bearer "+old)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 409 || !strings.Contains(w.Body.String(), `"code":"rotation_trust_changed"`) || strings.Contains(w.Body.String(), request.ReplacementSecret) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authenticated precommit trust conflict lost its fixed projection")
	}
}
