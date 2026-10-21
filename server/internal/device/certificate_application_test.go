package device

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

func TestCertificateAppliedHTTPAuthenticatesAndCorrelatesExactPublicReport(t *testing.T) {
	_, _, repo := certificateFixture(t)
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{61}, 32))
	hash, err := auth.HashPassword(secret)
	if err != nil {
		t.Fatal(err)
	}
	credential := Credential{TenantID: "fixture", Hash: hash}
	service := fixtureService(t, &lifecycleRepository{credential: credential})
	repo.credential, repo.found = credential, true
	data, err := os.ReadFile("../../../proto/examples/valid/certificate-applied-request.json")
	var input protocol.CertificateAppliedRequest
	if err != nil || json.Unmarshal(data, &input) != nil {
		t.Fatal("public application fixture")
	}
	repo.issued = &guicert.IssuedCertificate{ID: input.GenerationID, Generation: input.Generation, Fingerprint: input.LeafFingerprint}
	certificates, err := NewCertificates(service, repo)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	handler := testHTTP(t, service, &logs)
	handler.certificates = certificates
	post := func(input protocol.CertificateAppliedRequest, token string) *httptest.ResponseRecorder {
		data, _ := json.Marshal(input)
		r := requestHTTP(string(data))
		r.URL.Path = "/api/v1/devices/gui-certificate/applied"
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	var previous protocol.CertificateAppliedResponse
	expected := input
	expected.AgentProtocolVersion = protocol.Version
	for range 2 {
		w := post(input, secret)
		var result protocol.CertificateAppliedResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Validate() != nil || result.CertificateAppliedRequest != expected {
			t.Fatal("exact authenticated report failed", w.Code)
		}
		if previous.AcceptedAt != "" && previous != result {
			t.Fatal("confirmation retry changed its receipt")
		}
		previous = result
		var fields map[string]json.RawMessage
		if json.Unmarshal(w.Body.Bytes(), &fields) != nil || len(fields) != 9 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("unbounded/cacheable application response")
		}
		if bytes.Contains(w.Body.Bytes(), []byte(secret)) || bytes.Contains(logs.Bytes(), []byte(secret)) {
			t.Fatal("credential exposure")
		}
	}
	before := repo.calls
	if w := post(input, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{62}, 32))); w.Code != 401 || repo.calls != before {
		t.Fatal("bad credential reached application repository")
	}
	for _, version := range []string{"1.0.0", "1.2.0", "1.3.9", "2.0.0"} {
		changed := input
		changed.AgentProtocolVersion = version
		if w := post(changed, secret); w.Code != 400 || repo.calls != before {
			t.Fatal("unsupported application version reached repository", w.Code)
		}
	}
	for _, change := range []func(*protocol.CertificateAppliedRequest){func(v *protocol.CertificateAppliedRequest) { v.RequestID = "00000000-0000-0000-0000-000000000000" }, func(v *protocol.CertificateAppliedRequest) { v.Generation++ }, func(v *protocol.CertificateAppliedRequest) { v.LeafFingerprint = string(bytes.Repeat([]byte{'0'}, 64)) }} {
		changed := input
		change(&changed)
		if w := post(changed, secret); w.Code != 401 {
			t.Fatal("different material acknowledged", w.Code)
		}
	}
	repo.err = context.DeadlineExceeded
	if w := post(input, secret); w.Code != 503 || bytes.Contains(w.Body.Bytes(), []byte("deadline")) {
		t.Fatal("private dependency diagnostic exposed", w.Code)
	}
}
