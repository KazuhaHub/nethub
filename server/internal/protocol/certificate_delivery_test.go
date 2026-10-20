package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIssuedCertificateContractBindsOriginalPublicRequest(t *testing.T) {
	request, err := DecodeCertificateIssued(bytes.NewReader(example(t, "certificate-issued-request")))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	var original CertificateDelivery
	if json.Unmarshal(example(t, "certificate-issued-response"), &original) != nil || original.ValidateAt(now) != nil || original.Request.RequestID != request.RequestID || original.Request.CSRFingerprint != request.CSRFingerprint {
		t.Fatal("public delivered chain lost original request/key/name correlation")
	}
	var pending CertificateDelivery
	if json.Unmarshal(example(t, "certificate-issued-pending-response"), &pending) != nil || pending.Issued != nil || pending.ValidateAt(now) != nil {
		t.Fatal("pending original request delivery invalid")
	}
	for _, version := range []string{"1.0.0", "1.1.99", "1.2.0", "1.2.999+compatible-old"} {
		r := request
		r.AgentProtocolVersion = version
		if r.Validate() == nil {
			t.Fatal("old minor reached delivery")
		}
	}
	for _, version := range []string{"1.3.0", "1.4.1", "1.30.0-rc.1", "1.999999999999999999999999.0"} {
		r := request
		r.AgentProtocolVersion = version
		if r.Validate() != nil {
			t.Fatal("future compatible delivery minor rejected")
		}
	}
	request.AgentProtocolVersion = "2.0.0"
	if !errors.Is(request.Validate(), ErrIncompatibleVersion) {
		t.Fatal("incompatible delivery major accepted")
	}
	for _, corrupt := range []func(*CertificateDelivery){
		func(r *CertificateDelivery) { r.Request = nil },
		func(r *CertificateDelivery) { r.AssignedHost = "different.devices.example.com" },
		func(r *CertificateDelivery) { r.GUIKeyFingerprint = strings.Repeat("a", 64) },
		func(r *CertificateDelivery) { r.Request.CSRFingerprint = strings.Repeat("a", 64) },
		func(r *CertificateDelivery) { r.Issued.ID = "not-a-generation" },
		func(r *CertificateDelivery) { r.Issued.Generation = 0 },
		func(r *CertificateDelivery) { r.Issued.Generation = 2147483648 },
		func(r *CertificateDelivery) { r.Issued.LeafFingerprint = strings.Repeat("a", 64) },
		func(r *CertificateDelivery) { r.Issued.ChainPEM += "trailing response data" },
		func(r *CertificateDelivery) { r.Issued.ChainPEM = strings.Repeat("x", 32769) },
		func(r *CertificateDelivery) { r.Issued.NotBefore = "2026-01-01T00:00:00Z" },
		func(r *CertificateDelivery) { r.Issued.NotAfter = r.Issued.NotBefore },
		func(r *CertificateDelivery) { r.Issued.ValidUntil = "2026-10-19T11:59:59.000000Z" },
		func(r *CertificateDelivery) { r.Issued.ValidUntil = "2037-01-01T00:00:00.000000Z" },
		func(r *CertificateDelivery) { r.Issued.RenewAfter = r.Issued.ValidUntil },
		func(r *CertificateDelivery) { r.Issued.RenewAfter = r.Issued.NotBefore },
	} {
		var value CertificateDelivery
		if json.Unmarshal(example(t, "certificate-issued-response"), &value) != nil {
			t.Fatal("fixture unavailable")
		}
		corrupt(&value)
		if value.ValidateAt(now) == nil {
			t.Fatal("corrupt or unbound delivery accepted")
		}
	}
}

func TestIssuedRequestDecoderRejectsAmbiguousInput(t *testing.T) {
	valid := example(t, "certificate-issued-request")
	for _, suffix := range []string{`,"request_id":null}`, `,"csr_fingerprint":null}`, `,"issued":{"chain_pem":"not-input"},"issued":null}`} {
		input := append(bytes.Clone(valid[:bytes.LastIndexByte(valid, '}')]), []byte(suffix)...)
		if _, err := DecodeCertificateIssued(bytes.NewReader(input)); err == nil {
			t.Fatal("ambiguous delivery request accepted")
		}
	}
	fields := map[string]any{}
	if json.Unmarshal(valid, &fields) != nil {
		t.Fatal("fixture unavailable")
	}
	fields["future_optional"] = true
	data, _ := json.Marshal(fields)
	result, err := DecodeCertificateIssued(bytes.NewReader(data))
	if err != nil {
		t.Fatal("bounded future extension rejected")
	}
	encoded, _ := json.Marshal(result)
	if bytes.Contains(encoded, []byte("future_optional")) {
		t.Fatal("extension reached typed delivery operation")
	}
}
