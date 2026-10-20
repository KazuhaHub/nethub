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
	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

func TestCertificateIssuedHTTPBindsAuthenticatedOriginalRequest(t *testing.T) {
	_, _, repo := certificateFixture(t)
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{51}, 32))
	hash, err := auth.HashPassword(secret)
	if err != nil {
		t.Fatal(err)
	}
	credential := Credential{TenantID: "fixture", Hash: hash}
	lifecycle := &lifecycleRepository{credential: credential}
	service := fixtureService(t, lifecycle)
	repo.credential, repo.found = credential, true
	certificates, err := NewCertificates(service, repo)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	handler := testHTTP(t, service, &logs)
	handler.certificates = certificates
	input := protocol.CertificateIssuedRequest{Identity: protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: repo.record.DeviceID}, RequestID: repo.record.ID, CSRFingerprint: repo.record.Fingerprint}
	post := func(input protocol.CertificateIssuedRequest, token string) *httptest.ResponseRecorder {
		t.Helper()
		data, _ := json.Marshal(input)
		r := requestHTTP(string(data))
		r.URL.Path = "/api/v1/devices/gui-certificate/issued"
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	var pending protocol.CertificateDelivery
	w := post(input, secret)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &pending) != nil || pending.Validate() != nil || pending.Issued != nil {
		t.Fatal("authenticated pending delivery failed", w.Code)
	}
	data, err := os.ReadFile("../../../proto/examples/valid/certificate-issued-response.json")
	var example protocol.CertificateDelivery
	if err != nil || json.Unmarshal(data, &example) != nil || example.Validate() != nil {
		t.Fatal("public issued fixture invalid", err)
	}
	parse := func(value string) time.Time {
		v, err := time.Parse(protocol.CertificateTimeLayout, value)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	v := example.Issued
	repo.issued = &guicert.IssuedCertificate{ID: v.ID, Generation: v.Generation, PEM: []byte(v.ChainPEM), Fingerprint: v.LeafFingerprint, NotBefore: parse(v.NotBefore), NotAfter: parse(v.NotAfter), ValidUntil: parse(v.ValidUntil), RenewAfter: parse(v.RenewAfter)}
	for range 2 {
		w = post(input, secret)
		var result protocol.CertificateDelivery
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Validate() != nil || result.Issued.ID != v.ID || result.Issued.ChainPEM != v.ChainPEM || result.Request.RequestID != input.RequestID {
			t.Fatal("issued retry did not deliver the exact public generation", w.Code)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(w.Body.Bytes(), &fields) != nil || len(fields) != 6 {
			t.Fatal("delivery contains unexpected top-level metadata")
		}
		if bytes.Contains(w.Body.Bytes(), []byte(secret)) || bytes.Contains(logs.Bytes(), []byte(secret)) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("delivery exposed a credential or cacheable response")
		}
	}
	before := repo.calls
	if w := post(input, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{52}, 32))); w.Code != 401 || repo.calls != before {
		t.Fatal("invalid secret reached issued repository", w.Code)
	}
	old := input
	old.AgentProtocolVersion = "1.2.0"
	if w := post(old, secret); w.Code != 400 || repo.calls != before {
		t.Fatal("old delivery minor reached repository", w.Code)
	}
	wrong := input
	wrong.RequestID = "00000000-0000-0000-0000-000000000000"
	if w := post(wrong, secret); w.Code != 401 {
		t.Fatal("different request received issued material", w.Code)
	}
	repo.err = context.DeadlineExceeded
	if w := post(input, secret); w.Code != 503 || bytes.Contains(w.Body.Bytes(), []byte("deadline")) {
		t.Fatal("private delivery dependency diagnostic exposed", w.Code)
	}
	repo.err = nil
	repo.issued.PEM = append(repo.issued.PEM, []byte("modified")...)
	if w := post(input, secret); w.Code != 503 || bytes.Contains(w.Body.Bytes(), []byte(v.ChainPEM)) {
		t.Fatal("corrupt repository material reached the device", w.Code)
	}
}
