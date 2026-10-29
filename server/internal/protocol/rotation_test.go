package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotateRequestVersionAndJournalBinding(t *testing.T) {
	for _, version := range []string{"1.6.0", "1.7.0-rc.1", "1.999999999999999999999.0"} {
		r := RotateRequest{Identity: Identity{AgentProtocolVersion: version, DeviceID: "11111111-1111-4111-8111-111111111111"},
			OperationID: "22222222-2222-4222-8222-222222222222", ReplacementSecret: strings.Repeat("A", 43), ExpectedRelayCASHA256: strings.Repeat("a", 64)}
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := DecodeRotate(bytes.NewReader(data)); err != nil || got != r {
			t.Fatal("valid rotation request did not retain its journal binding")
		}
	}
	for _, version := range []string{"1.0.0", "1.5.99", "1.5.0+rotation"} {
		r := RotateRequest{Identity: Identity{AgentProtocolVersion: version, DeviceID: "11111111-1111-4111-8111-111111111111"}}
		if !errors.Is(r.Validate(), ErrRotationVersion) {
			t.Fatal("old protocol admitted credential rotation")
		}
	}
}

func TestRotateRequestRejectsAmbiguousOrMissingCandidates(t *testing.T) {
	valid := example(t, "rotate-request")
	var object map[string]any
	if json.Unmarshal(valid, &object) != nil {
		t.Fatal("rotation fixture unavailable")
	}
	for _, field := range []string{"agent_protocol_version", "device_id", "operation_id", "replacement_secret", "expected_relay_ca_sha256"} {
		for _, kind := range []string{"missing", "null", "object", "duplicate"} {
			t.Run(field+"/"+kind, func(t *testing.T) {
				copy := make(map[string]any, len(object))
				for k, v := range object {
					copy[k] = v
				}
				switch kind {
				case "missing":
					delete(copy, field)
				case "null":
					copy[field] = nil
				case "object":
					copy[field] = map[string]any{}
				}
				data, err := json.Marshal(copy)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "duplicate" {
					value, _ := json.Marshal(copy[field])
					data = append(data[:len(data)-1], []byte(fmt.Sprintf(",%q:%s}", field, value))...)
				}
				if _, err := DecodeRotate(bytes.NewReader(data)); err == nil {
					t.Fatal("ambiguous or missing field admitted")
				}
			})
		}
	}
	for _, id := range []string{"", "00000000-0000-0000-0000-000000000000", "22222222-2222-5222-8222-222222222222", "22222222-2222-4222-7222-222222222222", "22222222-2222-4222-8222-22222222222A"} {
		object["operation_id"] = id
		data, _ := json.Marshal(object)
		if _, err := DecodeRotate(bytes.NewReader(data)); err == nil {
			t.Fatal("noncanonical operation ID admitted")
		}
	}
}

func TestRotateSharedSchemaAndDecoderAgree(t *testing.T) {
	compiled := schemas(t)["rotate-request.schema.json"]
	for _, name := range []string{"rotate-old-peer", "rotate-zero-operation", "rotate-missing-candidate", "rotate-noncanonical-secret"} {
		data, err := os.ReadFile(filepath.Join(protocolRoot(t), "examples", "invalid", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if compiled.Validate(instance(t, data)) == nil {
			t.Fatal("schema admitted invalid rotation fixture")
		}
		if _, err := DecodeRotate(bytes.NewReader(data)); err == nil {
			t.Fatal("decoder admitted invalid rotation fixture")
		}
	}
}

func TestRotateRequestBoundsOptionalFieldsAndSecrets(t *testing.T) {
	var request map[string]any
	if json.Unmarshal(example(t, "rotate-request"), &request) != nil {
		t.Fatal("rotation fixture unavailable")
	}
	for i := range 16 {
		request[fmt.Sprintf("future_%d", i)] = true
	}
	data, _ := json.Marshal(request)
	if _, err := DecodeRotate(bytes.NewReader(data)); err != nil {
		t.Fatal("bounded forward-compatible fields refused")
	}
	request["future_overflow"] = true
	data, _ = json.Marshal(request)
	if _, err := DecodeRotate(bytes.NewReader(data)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("unbounded optional fields admitted")
	}
	for _, secret := range []string{strings.Repeat("A", 42) + "B", strings.Repeat("A", 43) + "=", strings.Repeat("A", 43) + "\n"} {
		r := RotateRequest{Identity: Identity{AgentProtocolVersion: Version, DeviceID: "11111111-1111-4111-8111-111111111111"},
			OperationID: "22222222-2222-4222-8222-222222222222", ReplacementSecret: secret}
		if err := r.Validate(); !errors.Is(err, ErrInvalidRequest) || strings.Contains(err.Error(), secret) {
			t.Fatal("noncanonical secret admitted or disclosed")
		}
	}
}
