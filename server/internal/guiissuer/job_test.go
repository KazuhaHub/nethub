package guiissuer

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

func snapshotFixture(t *testing.T) (databaseSnapshot, time.Time) {
	t.Helper()
	var response protocol.CertificateSettings
	data, err := os.ReadFile("../../../proto/examples/valid/certificate-submit-response.json")
	if err != nil || json.Unmarshal(data, &response) != nil || response.Validate() != nil {
		t.Fatal("signed CSR fixture unavailable", err)
	}
	der, _ := base64.StdEncoding.DecodeString(response.Request.CSRDER)
	// The public SPKI is extracted from the signed request, never a private key.
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(parsed.RawSubjectPublicKeyInfo)
	now := time.Now().UTC().Truncate(time.Microsecond)
	expires := now.Add(120 * time.Second)
	token := "34567890-3456-3456-3456-34567890abcd"
	job := databaseJob{ID: "45678901-4567-4567-4567-45678901abcd", TenantID: "56789012-5678-5678-5678-56789012abcd", DeviceID: response.DeviceID,
		RequestID: response.Request.RequestID, Generation: 1, State: "leased", Version: 2, LeaseToken: &token, LeaseExpires: &expires, NextAttempt: now, FailureCode: "none", Created: now, Updated: now, Deadline: now.Add(2 * time.Hour)}
	return databaseSnapshot{Job: job, Host: response.AssignedHost, Subdomain: "abcd1234", PublicKey: public, CSRHex: hex.EncodeToString(der), CSRFingerprint: response.Request.CSRFingerprint}, now
}

func TestPrivateSnapshotBindsCurrentWorkAndExcludesJSON(t *testing.T) {
	raw, now := snapshotFixture(t)
	data, _ := json.Marshal(raw)
	work, err := DecodeSnapshot(data, "devices.example.com", []string{"console.example.com"}, now)
	if err != nil || work.Host != raw.Host || work.Lease.ID != raw.Job.ID || work.Lease.Token != *raw.Job.LeaseToken {
		t.Fatal("current work failed independent binding", err)
	}
	for _, value := range []any{work, work.Lease} {
		encoded, err := json.Marshal(value)
		if err != nil || string(encoded) != "{}" {
			t.Fatal("private issuer metadata reached ordinary JSON")
		}
	}
	for _, domain := range []string{"other.example.com", "127.0.0.1", "EXAMPLE.com", "*.example.com", "localhost"} {
		if _, err := DecodeSnapshot(data, domain, nil, now); err == nil {
			t.Fatal("untrusted deployment suffix admitted")
		}
	}
	if _, err := DecodeSnapshot(data, "devices.example.com", []string{raw.Host}, now); err == nil {
		t.Fatal("excluded console/host admitted")
	}
}

func TestSnapshotRejectsStaleMalformedAndChangedBindings(t *testing.T) {
	for _, change := range []func(*databaseSnapshot, time.Time){
		func(r *databaseSnapshot, n time.Time) { r.Job.LeaseExpires = &n },
		func(r *databaseSnapshot, n time.Time) { v := n.Add(126 * time.Second); r.Job.LeaseExpires = &v },
		func(r *databaseSnapshot, n time.Time) { r.Job.Deadline = n },
		func(r *databaseSnapshot, n time.Time) { r.Job.State = "queued" },
		func(r *databaseSnapshot, n time.Time) { r.Job.LeaseToken = nil },
		func(r *databaseSnapshot, n time.Time) { r.Job.Version = 0 },
		func(r *databaseSnapshot, n time.Time) { r.Job.Failures = 5 },
		func(r *databaseSnapshot, n time.Time) { r.Job.Polls = 60 },
		func(r *databaseSnapshot, n time.Time) { r.Job.FailureCode = "policy" },
		func(r *databaseSnapshot, n time.Time) { r.Job.DeviceID = "not-an-id" },
		func(r *databaseSnapshot, n time.Time) { r.Host = "abcd1234.other.example.com" },
		func(r *databaseSnapshot, n time.Time) { r.Subdomain = "other123" },
		func(r *databaseSnapshot, n time.Time) { r.PublicKey = strings.Repeat("A", 122) },
		func(r *databaseSnapshot, n time.Time) { r.CSRFingerprint = strings.Repeat("0", 64) },
		func(r *databaseSnapshot, n time.Time) { r.CSRHex += "00" },
	} {
		raw, now := snapshotFixture(t)
		change(&raw, now)
		data, _ := json.Marshal(raw)
		if _, err := DecodeSnapshot(data, "devices.example.com", nil, now); err == nil {
			t.Fatal("invalid private snapshot admitted")
		}
	}
	raw, now := snapshotFixture(t)
	data, _ := json.Marshal(raw)
	for _, bad := range [][]byte{[]byte("null"), append(data, []byte("{}")...), []byte(strings.TrimSuffix(string(data), "}") + `,"job":{}}`), []byte(strings.Replace(string(data), `"state":"leased"`, `"state":"leased","state":"queued"`, 1))} {
		if _, err := DecodeSnapshot(bad, "devices.example.com", nil, now); err == nil {
			t.Fatal("ambiguous JSON admitted")
		}
	}
}
