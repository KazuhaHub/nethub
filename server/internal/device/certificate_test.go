package device

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

type certificateRepository struct {
	assignment     guicert.Assignment
	record         guicert.StoredRequest
	credential     Credential
	err, healthErr error
	found          bool
	calls          int
	issued         *guicert.IssuedCertificate
}

func (s *certificateRepository) Issued(_ context.Context, c Credential, id, requestID, fingerprint string) (guicert.StoredRequest, *guicert.IssuedCertificate, error) {
	s.calls++
	if c != s.credential || id != s.record.DeviceID || requestID != s.record.ID || fingerprint != s.record.Fingerprint || !s.found {
		return guicert.StoredRequest{}, nil, ErrDenied
	}
	if s.err != nil {
		return guicert.StoredRequest{}, nil, s.err
	}
	return s.record, s.issued, nil
}

func (s *certificateRepository) Health(context.Context) error { return s.healthErr }
func (s *certificateRepository) Settings(_ context.Context, c Credential, id string) (guicert.Assignment, *guicert.StoredRequest, error) {
	s.calls++
	if c != s.credential || id != s.record.DeviceID {
		return guicert.Assignment{}, nil, ErrDenied
	}
	if s.err != nil {
		return guicert.Assignment{}, nil, s.err
	}
	if !s.found {
		return s.assignment, nil, nil
	}
	return s.assignment, &s.record, nil
}
func (s *certificateRepository) Admit(_ context.Context, c Credential, id string, _ []byte) (guicert.StoredRequest, error) {
	s.calls++
	if c != s.credential || id != s.record.DeviceID {
		return guicert.StoredRequest{}, ErrDenied
	}
	if s.err != nil {
		return guicert.StoredRequest{}, s.err
	}
	s.found = true
	return s.record, nil
}

func certificateFixture(t *testing.T) (protocol.CertificateSettings, protocol.CertificateSubmit, *certificateRepository) {
	t.Helper()
	data, err := os.ReadFile("../../../proto/examples/valid/certificate-submit-response.json")
	var response protocol.CertificateSettings
	if err != nil || json.Unmarshal(data, &response) != nil || response.Validate() != nil {
		t.Fatal("certificate fixture unavailable", err)
	}
	der, _ := protocol.CertificateDER(response.Request.CSRDER)
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	stamp, _ := time.Parse("2006-01-02T15:04:05.000000Z", response.Request.CreatedAt)
	repo := &certificateRepository{assignment: guicert.Assignment{Host: response.AssignedHost, KeyFingerprint: response.GUIKeyFingerprint}, record: guicert.StoredRequest{ID: response.Request.RequestID, DeviceID: response.DeviceID, AssignedHost: response.AssignedHost, PublicKey: base64.RawURLEncoding.EncodeToString(parsed.RawSubjectPublicKeyInfo), Fingerprint: response.Request.CSRFingerprint, DER: der, CreatedAt: stamp}}
	return response, protocol.CertificateSubmit{Identity: response.Identity, CSRDER: response.Request.CSRDER}, repo
}

func TestCertificateHTTPAuthenticationAndReadback(t *testing.T) {
	expected, submit, repo := certificateFixture(t)
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{51}, 32))
	hash, err := auth.HashPassword(secret)
	if err != nil {
		t.Fatal(err)
	}
	credential := Credential{TenantID: "fixture", Hash: hash}
	lifecycle := &lifecycleRepository{credential: credential}
	service := fixtureService(t, lifecycle)
	repo.credential = credential
	certificates, err := NewCertificates(service, repo)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	handler := testHTTP(t, service, &log)
	handler.certificates = certificates
	post := func(path string, body any, headers []string) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		r := requestHTTP(string(data))
		r.URL.Path = "/api/v1/devices/gui-certificate/" + path
		for _, value := range headers {
			r.Header.Add("Authorization", value)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, headers := range [][]string{nil, {"Bearer " + strings.Repeat("A", 43)}, {"Bearer " + secret, "Bearer " + secret}} {
		before := repo.calls
		if w := post("settings", submit.Identity, headers); w.Code != http.StatusUnauthorized || repo.calls != before {
			t.Fatal("bad device credential reached request store", w.Code)
		}
	}
	authz := []string{"Bearer " + secret}
	w := post("settings", submit.Identity, authz)
	var response protocol.CertificateSettings
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Validate() != nil || response.Request != nil {
		t.Fatal("fresh assignment settings failed", w.Code)
	}
	w = post("request", submit, authz)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Request == nil || response.Request.CSRDER != expected.Request.CSRDER || response.Validate() != nil {
		t.Fatal("signed CSR upload/readback failed", w.Code)
	}
	w = post("settings", submit.Identity, authz)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Request.RequestID != expected.Request.RequestID {
		t.Fatal("original CSR recovery failed")
	}
	for _, test := range []struct {
		err  error
		code int
	}{{ErrDenied, 401}, {guicert.ErrConflict, 409}, {guicert.ErrRequest, 400}, {errors.New("private dependency diagnostic"), 503}} {
		repo.err = test.err
		w = post("request", submit, authz)
		if w.Code != test.code || strings.Contains(w.Body.String(), "private dependency") {
			t.Fatal("unsafe certificate error response", w.Code)
		}
	}
	repo.err = nil
	old := submit
	old.AgentProtocolVersion = "1.1.0"
	before := repo.calls
	if w := post("request", old, authz); w.Code != 400 || repo.calls != before {
		t.Fatal("old protocol reached certificate store")
	}
	// Existing lifecycle behavior remains compatible with 1.1 agents.
	identity := old.Identity
	encoded, _ := json.Marshal(identity)
	r := requestHTTP(string(encoded))
	r.URL.Path = "/api/v1/devices/unenroll"
	r.Header.Set("Authorization", "Bearer "+secret)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("old agent removal was broken", w.Code)
	}
	repo.healthErr = ErrUnavailable
	r = requestHTTP("")
	r.Method = http.MethodGet
	r.URL.Path = "/healthz"
	r.ContentLength = 0
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal("failed certificate guard left service ready")
	}
	for _, needle := range []string{secret, hash, submit.CSRDER, repo.record.PublicKey, "private dependency diagnostic"} {
		if strings.Contains(log.String(), needle) {
			t.Fatal("certificate API logged protected input")
		}
	}
}

func TestCertificateHTTPDisabledAndOutputCorrelation(t *testing.T) {
	expected, _, repo := certificateFixture(t)
	service := fixtureService(t, &fakeRepository{})
	var log bytes.Buffer
	handler := testHTTP(t, service, &log)
	r := requestHTTP(`{}`)
	r.URL.Path = "/api/v1/devices/gui-certificate/settings"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("unconfigured certificate API exposed")
	}
	for _, change := range []func(*certificateRepository){
		func(r *certificateRepository) { r.record.DeviceID = "00000000-0000-0000-0000-000000000000" },
		func(r *certificateRepository) { r.record.AssignedHost = "other.example.com" },
		func(r *certificateRepository) { r.assignment.KeyFingerprint = strings.Repeat("0", 64) },
		func(r *certificateRepository) { r.record.Fingerprint = strings.Repeat("0", 64) },
	} {
		_, _, fresh := certificateFixture(t)
		change(fresh)
		if _, err := certificateResponse(expected.Identity, fresh.assignment, &fresh.record); !errors.Is(err, ErrUnavailable) {
			t.Fatal("repository identity mismatch reached response")
		}
	}
	if _, err := certificateResponse(expected.Identity, repo.assignment, &repo.record); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateHTTPRejectsBeforeAuthentication(t *testing.T) {
	expected, _, repo := certificateFixture(t)
	service := fixtureService(t, &fakeRepository{})
	certificates, err := NewCertificates(service, repo)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	handler := testHTTP(t, service, &log)
	handler.certificates = certificates
	for _, test := range []struct {
		name   string
		code   int
		change func(*http.Request)
	}{
		{"method", 405, func(r *http.Request) { r.Method = http.MethodGet }},
		{"host", 400, func(r *http.Request) { r.Host = "other.example.com" }},
		{"origin", 403, func(r *http.Request) { r.Header.Set("Origin", "https://other.example.com") }},
		{"query", 400, func(r *http.Request) { r.URL.RawQuery = "secret=not-allowed" }},
		{"empty_query", 400, func(r *http.Request) { r.URL.ForceQuery = true }},
		{"encoded_path", 404, func(r *http.Request) { r.URL.RawPath = "/api/v1/devices/gui-certificate/%73ettings" }},
		{"type", 415, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
		{"encoding", 415, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"authorization", 401, func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+strings.Repeat("A", 43)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, _ := json.Marshal(expected.Identity)
			r := requestHTTP(string(data))
			r.URL.Path = "/api/v1/devices/gui-certificate/settings"
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 43))
			test.change(r)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.code || repo.calls != 0 {
				t.Fatal("invalid certificate request reached authentication/store", w.Code)
			}
		})
	}
}
