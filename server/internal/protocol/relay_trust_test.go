package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRelayTrustVersionAndStrictRequests(t *testing.T) {
	data := example(t, "relay-trust-applied-request")
	r, err := DecodeRelayTrustApplied(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.5.0", "1.6.0-rc.1", "1.999999999999999999999.0"} {
		r.AgentProtocolVersion = version
		if r.Validate() != nil {
			t.Fatal("valid trust peer refused")
		}
	}
	for _, version := range []string{"1.0.0", "1.4.99", "2.0.0", "1.05.0"} {
		r.AgentProtocolVersion = version
		if r.Validate() == nil {
			t.Fatal("unsupported trust peer accepted")
		}
	}
	for _, suffix := range []string{`,"generation":2}`, `,"generation":null}`, `,"generation":true}`, `,"generation":1.5}`} {
		duplicate := strings.TrimSuffix(strings.TrimSpace(string(data)), "}") + suffix
		if _, err := DecodeRelayTrustApplied(strings.NewReader(duplicate)); err == nil {
			t.Fatal("ambiguous trust request accepted")
		}
	}
	var reply RelayTrustAppliedResponse
	if json.Unmarshal(example(t, "relay-trust-applied-response"), &reply) != nil || reply.Validate() != nil {
		t.Fatal("shared trust acceptance invalid")
	}
	for _, schema := range []string{"relay-trust-settings-request", "relay-trust-applied-request"} {
		if err := schemas(t)[schema+".schema.json"].Validate(instance(t, example(t, schema))); err != nil {
			t.Fatal(err)
		}
	}
}
