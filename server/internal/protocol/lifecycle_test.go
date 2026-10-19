package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestLifecycleDecoders(t *testing.T) {
	for _, name := range []string{"status", "unenroll"} {
		t.Run(name, func(t *testing.T) {
			data := example(t, name+"-request")
			decode := func(value []byte) error {
				if name == "status" {
					_, err := DecodeStatus(bytes.NewReader(value))
					return err
				}
				_, err := DecodeIdentity(bytes.NewReader(value))
				return err
			}
			if err := decode(data); err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			json.Unmarshal(data, &value)
			for key := range value {
				copy := map[string]any{}
				for k, v := range value {
					copy[k] = v
				}
				delete(copy, key)
				raw, _ := json.Marshal(copy)
				if decode(raw) == nil {
					t.Fatalf("missing %s accepted", key)
				}
			}
			for _, raw := range []string{`{"device_id":"x","device_id":"y"}`, `{"device_id":null}`, string(data) + ` {}`, strings.Repeat(" ", MaxBodyBytes+1)} {
				if decode([]byte(raw)) == nil {
					t.Fatal("invalid body accepted")
				}
			}
			value["agent_protocol_version"] = "2.0.0"
			raw, _ := json.Marshal(value)
			if !errors.Is(decode(raw), ErrIncompatibleVersion) {
				t.Fatal("version not rejected")
			}
			value["agent_protocol_version"] = Version
			value["device_id"] = "12345678-1234-1234-1234-123456789ABC"
			raw, _ = json.Marshal(value)
			if decode(raw) == nil {
				t.Fatal("uppercase UUID accepted")
			}
		})
	}
}

func TestStatusNullsAndHealthBounds(t *testing.T) {
	var value map[string]any
	json.Unmarshal(example(t, "status-request"), &value)
	value["last_reconcile_success"] = nil
	value["last_reconcile_at"] = nil
	raw, _ := json.Marshal(value)
	if _, err := DecodeStatus(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	for key, bad := range map[string]any{"service_state": "online", "last_reconcile_success": "true", "last_reconcile_at": "2026-10-18T00:00:00Z", "platform_version": strings.Repeat("x", 129), "agent_version": "line\nbreak"} {
		copy := map[string]any{}
		for k, v := range value {
			copy[k] = v
		}
		copy[key] = bad
		raw, _ := json.Marshal(copy)
		if _, err := DecodeStatus(bytes.NewReader(raw)); err == nil {
			t.Fatalf("bad %s accepted", key)
		}
	}
}
