package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func protocolRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../../proto")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func schemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	files, err := filepath.Glob(filepath.Join(protocolRoot(t), "v1", "*.schema.json"))
	if err != nil || len(files) != 18 {
		t.Fatalf("expected eighteen shared schemas, got %d: %v", len(files), err)
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource(path, document); err != nil {
			t.Fatal(err)
		}
		identifier := document.(map[string]any)["$id"].(string)
		if err := compiler.AddResource(identifier, document); err != nil {
			t.Fatal(err)
		}
	}
	result := make(map[string]*jsonschema.Schema)
	for _, path := range files {
		schema, err := compiler.Compile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[filepath.Base(path)] = schema
	}
	return result
}

func example(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(protocolRoot(t), "examples", "valid", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func instance(t *testing.T, data []byte) any {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSharedExamples(t *testing.T) {
	compiled := schemas(t)
	var entries []struct {
		Path   string `json:"path"`
		Schema string `json:"schema"`
		Valid  bool   `json:"valid"`
	}
	manifest, err := os.ReadFile(filepath.Join(protocolRoot(t), "examples", "manifest.json"))
	if err != nil || json.Unmarshal(manifest, &entries) != nil || len(entries) == 0 {
		t.Fatal("shared example manifest is unavailable")
	}
	covered := map[string]bool{}
	for _, entry := range entries {
		t.Run(entry.Path, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(protocolRoot(t), "examples", entry.Path))
			if err != nil {
				t.Fatal(err)
			}
			schema, exists := compiled[entry.Schema]
			if !exists {
				t.Fatal("example refers to an unknown schema")
			}
			if valid := schema.Validate(instance(t, data)) == nil; valid != entry.Valid {
				t.Fatalf("schema result=%v; expected=%v", valid, entry.Valid)
			}
			if entry.Schema == "enroll-request.schema.json" {
				_, err := DecodeEnroll(bytes.NewReader(data))
				if (err == nil) != entry.Valid {
					t.Fatalf("Go parser disagrees with shared example: %v", err)
				}
			}
		})
		if entry.Valid {
			covered[entry.Schema] = true
		}
	}
	if len(covered) != len(compiled)-1 {
		t.Fatal("a message schema lacks a valid shared example")
	}
}

func TestWireTypesRoundTripThroughSharedSchemas(t *testing.T) {
	compiled := schemas(t)
	for name, target := range map[string]any{
		"enroll-request": &EnrollRequest{}, "enroll-response": &EnrollResponse{},
		"rotate-request": &RotateRequest{}, "rotate-response": &RotateResponse{},
		"unenroll-request": &UnenrollRequest{}, "unenroll-response": &UnenrollResponse{},
		"status-request": &StatusRequest{}, "status-response": &StatusResponse{},
		"domain-claim":                 &ClaimPayload{},
		"certificate-settings-request": &Identity{}, "certificate-submit-request": &CertificateSubmit{},
		"certificate-settings-response": &CertificateSettings{}, "certificate-submit-response": &CertificateSettings{},
		"certificate-issued-request": &CertificateIssuedRequest{}, "certificate-issued-response": &CertificateDelivery{},
		"certificate-applied-request": &CertificateAppliedRequest{}, "certificate-applied-response": &CertificateAppliedResponse{},
	} {
		t.Run(name, func(t *testing.T) {
			data := example(t, name)
			if err := json.Unmarshal(data, target); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(target)
			if err != nil {
				t.Fatal(err)
			}
			if err := compiled[name+".schema.json"].Validate(instance(t, encoded)); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(instance(t, data), instance(t, encoded)) {
				t.Fatal("wire type changed or discarded a required field")
			}
		})
	}
	version, err := os.ReadFile(filepath.Join(protocolRoot(t), "VERSION"))
	if err != nil || strings.TrimSpace(string(version)) != Version {
		t.Fatal("Go version differs from shared protocol version")
	}
}

func TestEnrollCompatibilityAndExtensionIsolation(t *testing.T) {
	var fields map[string]any
	if err := json.Unmarshal(example(t, "enroll-request"), &fields); err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"opnsense", "openwrt", "vyos", "future-router"} {
		fields["platform"] = platform
		fields["agent_protocol_version"] = "1.20.3-rc.1+build.2"
		fields["future_optional"] = map[string]bool{"hint": true}
		fields["Platform"] = "must-not-override-the-known-field"
		encoded, _ := json.Marshal(fields)
		request, err := DecodeEnroll(bytes.NewReader(encoded))
		if err != nil || request.Platform != platform {
			t.Fatalf("bounded future platform/extension rejected: %v", err)
		}
		output, _ := json.Marshal(request)
		if bytes.Contains(output, []byte("future_optional")) || bytes.Contains(output, []byte("must-not-override")) {
			t.Fatal("unknown fields reached the typed request")
		}
	}
	for _, version := range []string{"0.9.0", "2.0.0"} {
		fields["agent_protocol_version"] = version
		encoded, _ := json.Marshal(fields)
		if _, err := DecodeEnroll(bytes.NewReader(encoded)); !errors.Is(err, ErrIncompatibleVersion) {
			t.Fatalf("incompatible major: %v", err)
		}
	}
	for _, version := range []string{"1.0", "01.0.0", "1.0.0-01", "1.0.0+", strings.Repeat("1", 65)} {
		if !errors.Is(CompatibleVersion(version), ErrInvalidRequest) {
			t.Fatal("invalid SemVer accepted")
		}
	}
}

func TestEnrollDecoderRejectsAmbiguousOrUnboundedInputs(t *testing.T) {
	data := strings.TrimSpace(string(example(t, "enroll-request")))
	var good map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &good); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"duplicate":         strings.TrimSuffix(data, "}") + `,"platform":"vyos"}`,
		"escaped_duplicate": strings.TrimSuffix(data, "}") + `,"plat\u0066orm":"vyos"}`,
		"nested_duplicate":  strings.TrimSuffix(data, "}") + `,"extra":{"same":1,"same":2}}`,
		"multiple_values":   data + `{}`, "null": `null`, "array": `[]`,
		"oversized":            data + strings.Repeat(" ", MaxBodyBytes),
		"deep_extension":       strings.TrimSuffix(data, "}") + `,"extra":` + strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18) + `}`,
		"long_extension_array": strings.TrimSuffix(data, "}") + `,"extra":[` + strings.Repeat("0,", 256) + `0]}`,
		"invalid_utf8":         strings.Replace(data, "router", "r\xffuter", 1),
	}
	for _, field := range []string{"agent_protocol_version", "enroll_token", "platform", "platform_version", "agent_version", "capabilities", "hostname", "cluster_hint"} {
		for _, value := range []json.RawMessage{nil, []byte("null")} {
			changed := make(map[string]json.RawMessage)
			for key, original := range good {
				changed[key] = original
			}
			name := "missing_" + field
			if value == nil {
				delete(changed, field)
			} else {
				changed[field] = value
				name = "null_" + field
			}
			encoded, _ := json.Marshal(changed)
			cases[name] = string(encoded)
		}
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			request, err := DecodeEnroll(strings.NewReader(input))
			if err == nil || request.EnrollToken != "" {
				t.Fatal("invalid request accepted or returned credential-bearing state")
			}
			if strings.Contains(err.Error(), strings.Repeat("A", 43)) {
				t.Fatal("parser diagnostic exposed input")
			}
		})
	}
}
