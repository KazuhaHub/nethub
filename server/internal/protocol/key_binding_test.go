package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestOptionalEnrollmentKeyBinding(t *testing.T) {
	encoded := example(t, "enroll-bound-request")
	request, err := DecodeEnroll(bytes.NewReader(encoded))
	if err != nil || request.GUIPublicKey == "" {
		t.Fatalf("bound request: %v", err)
	}
	output, _ := json.Marshal(request)
	if !bytes.Equal(normalized(t, encoded), normalized(t, output)) {
		t.Fatal("key binding discarded")
	}
	var fields map[string]any
	_ = json.Unmarshal(encoded, &fields)
	for _, invalid := range []any{nil, "", true, "not-a-key", request.GUIPublicKey + "=", request.GUIPublicKey[:121] + "B"} {
		fields["gui_public_key"] = invalid
		body, _ := json.Marshal(fields)
		value, err := DecodeEnroll(bytes.NewReader(body))
		if err == nil || value.EnrollToken != "" {
			t.Fatal("invalid key accepted or credential returned")
		}
	}
	delete(fields, "gui_public_key")
	fields["agent_protocol_version"] = "1.0.0"
	body, _ := json.Marshal(fields)
	if _, err := DecodeEnroll(bytes.NewReader(body)); err != nil {
		t.Fatal("legacy unbound request rejected")
	}
}

func normalized(t *testing.T, data []byte) []byte {
	t.Helper()
	var v any
	if json.Unmarshal(data, &v) != nil {
		t.Fatal("invalid test JSON")
	}
	result, _ := json.Marshal(v)
	return result
}
