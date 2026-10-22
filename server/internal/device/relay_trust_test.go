package device

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

type trustRepositoryFixture struct {
	credential Credential
	generation *relaytrust.Generation
	at         time.Time
	calls      int
}

func (f *trustRepositoryFixture) Health(context.Context) error { return nil }
func (f *trustRepositoryFixture) Current(_ context.Context, c Credential, _ string) (*relaytrust.Generation, error) {
	f.calls++
	if c != f.credential {
		return nil, ErrDenied
	}
	return f.generation, nil
}
func (f *trustRepositoryFixture) AcknowledgeReport(_ context.Context, c Credential, _ string, r relaytrust.Report) (time.Time, error) {
	f.calls++
	if c != f.credential {
		return time.Time{}, ErrDenied
	}
	if f.generation == nil || r.GenerationID != f.generation.ID || r.Number != f.generation.Number || r.Fingerprint != f.generation.Bundle().Fingerprint() {
		return time.Time{}, relaytrust.ErrChanged
	}
	if f.at.IsZero() {
		f.at = time.Now().UTC().Truncate(time.Microsecond)
	}
	return f.at, nil
}

func TestRelayTrustHTTPReusesAuthenticationAndReportsPendingState(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{52}, 32))
	hash, err := auth.HashPassword(secret)
	if err != nil {
		t.Fatal(err)
	}
	credential := Credential{TenantID: "fixture", Hash: hash}
	lifecycle := &lifecycleRepository{credential: credential}
	service := fixtureService(t, lifecycle)
	repo := &trustRepositoryFixture{credential: credential}
	trust, err := NewRelayTrust(service, repo)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	handler := testHTTP(t, service, &log)
	handler.relayTrust = trust
	data, err := os.ReadFile("../../../proto/examples/valid/relay-trust-applied-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var report protocol.RelayTrustAppliedRequest
	if json.Unmarshal(data, &report) != nil {
		t.Fatal("shared trust report")
	}
	post := func(action string, input any, authorization []string) *httptest.ResponseRecorder {
		t.Helper()
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		r := requestHTTP(string(data))
		r.URL.Path = "/api/v1/devices/relay-trust/" + action
		for _, value := range authorization {
			r.Header.Add("Authorization", value)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, headers := range [][]string{nil, {"Bearer " + secret, "Bearer " + secret}, {"Bearer " + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{53}, 32))}} {
		before := repo.calls
		if w := post("settings", report.Identity, headers); w.Code != 401 || repo.calls != before {
			t.Fatal("invalid credential reached trust store", w.Code)
		}
	}
	old := report.Identity
	old.AgentProtocolVersion = "1.4.99"
	if w := post("settings", old, []string{"Bearer " + secret}); w.Code != 400 {
		t.Fatal("old peer accepted", w.Code)
	}
	w := post("settings", report.Identity, []string{"Bearer " + secret})
	var pending protocol.RelayTrustSettings
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &pending) != nil || pending.Desired != nil || pending.DeviceID != report.DeviceID {
		t.Fatal("pending trust settings", w.Code)
	}
	if w := post("applied", report, []string{"Bearer " + secret}); w.Code != 409 {
		t.Fatal("stale trust report not refreshable", w.Code)
	}
	if bytes.Contains(log.Bytes(), []byte(secret)) {
		t.Fatal("device secret logged")
	}
}
