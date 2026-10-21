package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

func testRuntimeCertificateRequest(t *testing.T, f *enrollmentFixture, client *http.Client, address string, enrollment protocol.EnrollResponse, key *ecdsa.PrivateKey) func(string, any) (int, []byte) {
	t.Helper()
	post := func(action string, input any) (int, []byte) {
		t.Helper()
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(f.ctx, http.MethodPost, "http://"+address+"/api/v1/devices/gui-certificate/"+action, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = "console.example.com"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+enrollment.DeviceSecret)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("compiled certificate API request failed")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxBodyBytes+1))
		if err != nil || len(body) > protocol.MaxBodyBytes || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("unbounded/cacheable certificate response")
		}
		return response.StatusCode, body
	}
	identity := protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: enrollment.DeviceID}
	status, body := post("settings", identity)
	var settings protocol.CertificateSettings
	if status != 200 || json.Unmarshal(body, &settings) != nil || settings.Validate() != nil || settings.Request != nil || settings.DeviceID != enrollment.DeviceID || settings.GUIKeyFingerprint != enrollment.GUIKeyFingerprint || settings.AssignedHost != enrollment.Subdomain+".devices.example.com" {
		t.Fatal("compiled settings did not match committed enrollment", status)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{settings.AssignedHost}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
	if err != nil {
		t.Fatal(err)
	}
	submit := protocol.CertificateSubmit{Identity: identity, CSRDER: base64.StdEncoding.EncodeToString(der)}
	// Fail after signed-request/audit insertion, inside the same transaction.
	// The explicitly disposable fixture restores its original grant immediately.
	func() {
		if _, err := f.owner.ExecContext(f.ctx, `REVOKE EXECUTE ON FUNCTION enqueue_gui_certificate_request(uuid) FROM nethub_authz`); err != nil {
			t.Fatal("fixture queue grant fault", err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `GRANT EXECUTE ON FUNCTION enqueue_gui_certificate_request(uuid) TO nethub_authz`); err != nil {
				t.Error("fixture queue grant restoration", err)
			}
		}()
		if status, _ := post("request", submit); status != 503 {
			t.Fatal("compiled admission acknowledged unqueued work", status)
		}
		var requests, jobs, audits int
		if err := f.owner.QueryRowContext(f.ctx, `SELECT
 (SELECT count(*) FROM gui_certificate_requests WHERE device_id=$1),
 (SELECT count(*) FROM gui_certificate_jobs WHERE device_id=$1),
 (SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action IN ('device.certificate_requested','device.certificate_queued'))`, enrollment.DeviceID).Scan(&requests, &jobs, &audits); err != nil || requests != 0 || jobs != 0 || audits != 0 {
			t.Fatal("queue failure left a committed request, job or audit", err)
		}
	}()
	status, body = post("request", submit)
	if status != 200 || json.Unmarshal(body, &settings) != nil || settings.Validate() != nil || settings.Request == nil || settings.Request.CSRDER != submit.CSRDER {
		t.Fatal("compiled CSR admission failed", status)
	}
	saved := *settings.Request
	for _, action := range []string{"request", "settings"} {
		var input any = identity
		if action == "request" {
			input = submit
		}
		status, body = post(action, input)
		if status != 200 || json.Unmarshal(body, &settings) != nil || settings.Validate() != nil || settings.Request == nil || *settings.Request != saved {
			t.Fatal("compiled retry/readback changed original CSR")
		}
	}
	changed, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{settings.AssignedHost}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
	if err != nil {
		t.Fatal(err)
	}
	conflict := submit
	conflict.CSRDER = base64.StdEncoding.EncodeToString(changed)
	if status, _ := post("request", conflict); status != 409 {
		t.Fatal("compiled API replaced changed signed bytes", status)
	}
	wrong, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"other.example.com"}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
	if err != nil {
		t.Fatal(err)
	}
	invalid := submit
	invalid.CSRDER = base64.StdEncoding.EncodeToString(wrong)
	if status, _ := post("request", invalid); status != 400 {
		t.Fatal("compiled API admitted wrong SAN", status)
	}
	var stored []byte
	if err := f.owner.QueryRowContext(f.ctx, `SELECT csr_der FROM gui_certificate_requests WHERE device_id=$1`, enrollment.DeviceID).Scan(&stored); err != nil || !bytes.Equal(stored, der) {
		t.Fatal("compiled public response differs from committed CSR", err)
	}
	var jobs, generations, requests, queued int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT
 (SELECT count(*) FROM gui_certificate_jobs WHERE request_id=$1 AND generation=1 AND state='queued'),
 (SELECT count(*) FROM gui_certificate_jobs WHERE request_id=$1),
 (SELECT count(*) FROM audit_log WHERE target_device_id=$2 AND action='device.certificate_requested'),
 (SELECT count(*) FROM audit_log WHERE target_device_id=$2 AND action='device.certificate_queued')`, saved.RequestID, enrollment.DeviceID).Scan(&jobs, &generations, &requests, &queued); err != nil || jobs != 1 || generations != 1 || requests != 1 || queued != 1 {
		t.Fatal("compiled retries duplicated initial work or audit", err)
	}
	t.Log("Compiled authenticated CSR admission and initial queue committed atomically; queue-grant failure rolled back request/job/audits and exact retries retained one generation and audit pair")
	t.Log("Compiled authz certificate settings, bound CSR submission, exact retries/recovery, conflict and wrong-SAN checks passed against genuine PostgreSQL")
	return post
}
