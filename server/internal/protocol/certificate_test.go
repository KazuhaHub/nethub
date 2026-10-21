package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCertificateContractValidation(t *testing.T) {
	input := example(t, "certificate-submit-request")
	request, err := DecodeCertificateSubmit(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	var response CertificateSettings
	if err := json.Unmarshal(example(t, "certificate-submit-response"), &response); err != nil || response.Validate() != nil {
		t.Fatal("public signed CSR fixture failed actual validation", err)
	}
	if response.Request.CSRDER != request.CSRDER {
		t.Fatal("submit and readback fixtures disagree")
	}
	for _, version := range []string{"1.0.0", "1.1.99", "1.1.0-rc.1"} {
		r := request
		r.AgentProtocolVersion = version
		if !errors.Is(r.Validate(), ErrCertificateVersion) {
			t.Fatal("old minor admitted certificate upload")
		}
	}
	for _, version := range []string{"1.2.0", "1.3.0", "1.20.0", "1.999999999999999999999999.0"} {
		r := request
		r.AgentProtocolVersion = version
		if r.Validate() != nil {
			t.Fatal("compatible future minor rejected")
		}
	}
	for _, version := range []string{"2.0.0", "0.9.0"} {
		r := request
		r.AgentProtocolVersion = version
		if !errors.Is(r.Validate(), ErrIncompatibleVersion) {
			t.Fatal("incompatible major admitted")
		}
	}
	for _, value := range []string{"", request.CSRDER + "\n", strings.TrimRight(request.CSRDER, "="), "AA==\n", base64.StdEncoding.EncodeToString(make([]byte, 4097)), "_w=="} {
		if value == request.CSRDER {
			continue
		}
		if _, err := CertificateDER(value); err == nil {
			t.Fatal("noncanonical or unbounded DER encoding admitted")
		}
	}
	for _, change := range []func(*CertificateSettings){
		func(r *CertificateSettings) { r.AssignedHost = "other.example.com" },
		func(r *CertificateSettings) { r.GUIKeyFingerprint = strings.Repeat("0", 64) },
		func(r *CertificateSettings) { r.Request.CSRFingerprint = strings.Repeat("0", 64) },
		func(r *CertificateSettings) { r.Request.CreatedAt = "2026-02-30T00:00:00.000000Z" },
		func(r *CertificateSettings) { r.Request.RequestID = "not-an-id" },
		func(r *CertificateSettings) {
			der, _ := base64.StdEncoding.DecodeString(r.Request.CSRDER)
			der[len(der)-1] ^= 1
			r.Request.CSRDER = base64.StdEncoding.EncodeToString(der)
		},
	} {
		var changed CertificateSettings
		json.Unmarshal(example(t, "certificate-submit-response"), &changed)
		change(&changed)
		if changed.Validate() == nil {
			t.Fatal("mismatched certificate settings accepted")
		}
	}
}

func TestCertificateDecodersIsolateFieldsAndRejectAmbiguity(t *testing.T) {
	data := strings.TrimSpace(string(example(t, "certificate-submit-request")))
	for _, suffix := range []string{`,"csr_der":"AA=="}`, `,"c\u0073r_der":"AA=="}`, `,"extra":{"same":1,"same":2}}`} {
		if _, err := DecodeCertificateSubmit(strings.NewReader(strings.TrimSuffix(data, "}") + suffix)); err == nil {
			t.Fatal("duplicate field accepted")
		}
	}
	if _, err := DecodeCertificateSubmit(strings.NewReader(data + "{}")); err == nil {
		t.Fatal("multiple JSON values accepted")
	}
	var object map[string]any
	json.Unmarshal([]byte(data), &object)
	object["CSRDER"] = "must-not-override"
	object["tenant_id"] = "untrusted"
	object["assigned_host"] = "untrusted.example.com"
	encoded, _ := json.Marshal(object)
	r, err := DecodeCertificateSubmit(bytes.NewReader(encoded))
	if err != nil || r.CSRDER != object["csr_der"] {
		t.Fatal("extension overwrote trusted input")
	}
	for _, field := range []string{"agent_protocol_version", "device_id", "csr_der"} {
		changed := map[string]any{}
		for k, v := range object {
			changed[k] = v
		}
		changed[field] = nil
		encoded, _ := json.Marshal(changed)
		if _, err := DecodeCertificateSubmit(bytes.NewReader(encoded)); err == nil {
			t.Fatal("null required field accepted")
		}
	}
}
