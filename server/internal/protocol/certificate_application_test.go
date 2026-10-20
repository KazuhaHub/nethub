package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCertificateApplicationVersionAndBindings(t *testing.T) {
	var input CertificateAppliedRequest
	if json.Unmarshal(example(t, "certificate-applied-request"), &input) != nil || input.Validate() != nil {
		t.Fatal("valid application request")
	}
	for _, version := range []string{"1.4.0", "1.5.1", "1.40.0-rc.1", "1.99999999999999999999999.0"} {
		changed := input
		changed.AgentProtocolVersion = version
		if changed.Validate() != nil {
			t.Fatal("compatible application version rejected")
		}
	}
	for _, version := range []string{"1.0.0", "1.1.0", "1.2.0", "1.3.9"} {
		changed := input
		changed.AgentProtocolVersion = version
		if !errors.Is(changed.Validate(), ErrCertificateApplicationVersion) {
			t.Fatal("old application minor accepted")
		}
	}
	for _, change := range []func(*CertificateAppliedRequest){func(v *CertificateAppliedRequest) { v.Generation = 0 }, func(v *CertificateAppliedRequest) { v.Generation = 2147483648 }, func(v *CertificateAppliedRequest) { v.GenerationID = "bad" }, func(v *CertificateAppliedRequest) { v.CSRFingerprint = strings.Repeat("0", 63) }, func(v *CertificateAppliedRequest) { v.LeafFingerprint = strings.Repeat("A", 64) }} {
		changed := input
		change(&changed)
		if changed.Validate() == nil {
			t.Fatal("invalid generation binding accepted")
		}
	}
	var response CertificateAppliedResponse
	if json.Unmarshal(example(t, "certificate-applied-response"), &response) != nil || response.Validate() != nil {
		t.Fatal("valid application response")
	}
	response.Accepted = false
	if response.Validate() == nil {
		t.Fatal("unaccepted response")
	}
	response.Accepted = true
	response.AcceptedAt = "2026-10-20T00:00:00Z"
	if response.Validate() == nil {
		t.Fatal("noncanonical timestamp")
	}
}

func TestCertificateApplicationDecoderRejectsAmbiguityAndKeepsOnlyKnownFields(t *testing.T) {
	data := strings.TrimSpace(string(example(t, "certificate-applied-request")))
	for _, bad := range []string{data + `{}`, strings.TrimSuffix(data, "}") + `,"generation":2}`, strings.TrimSuffix(data, "}") + `,"gener\u0061tion":2}`, strings.Replace(data, `"generation": 1`, `"generation": 1.0`, 1), data + strings.Repeat(" ", MaxBodyBytes)} {
		if _, err := DecodeCertificateApplied(strings.NewReader(bad)); err == nil {
			t.Fatal("ambiguous application report accepted")
		}
	}
	withExtra := strings.TrimSuffix(data, "}") + `,"Generation":8,"future_optional":true}`
	value, err := DecodeCertificateApplied(strings.NewReader(withExtra))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(value)
	if bytes.Contains(encoded, []byte("future_optional")) || bytes.Contains(encoded, []byte(`"Generation"`)) {
		t.Fatal("extensions reached typed report")
	}
}
