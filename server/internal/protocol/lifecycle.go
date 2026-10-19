package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
)

var deviceIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func (r Identity) Validate() error {
	if err := CompatibleVersion(r.AgentProtocolVersion); err != nil {
		return err
	}
	if !deviceIDPattern.MatchString(r.DeviceID) {
		return ErrInvalidRequest
	}
	return nil
}

func ValidDeviceSecret(secret string) bool {
	data, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	return err == nil && len(secret) == 43 && len(data) == 32
}

func selectedLifecycle(reader io.Reader, fields []string, nullable map[string]bool) ([]byte, error) {
	object, err := boundedjson.Object(reader)
	if err != nil || len(object) > len(fields)+16 {
		return nil, ErrInvalidRequest
	}
	known := make(map[string]json.RawMessage, len(fields))
	for _, key := range fields {
		value, ok := object[key]
		if !ok || !nullable[key] && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrInvalidRequest
		}
		known[key] = value
	}
	return json.Marshal(known)
}

func DecodeIdentity(reader io.Reader) (Identity, error) {
	var r Identity
	data, err := selectedLifecycle(reader, []string{"agent_protocol_version", "device_id"}, nil)
	if err != nil || json.Unmarshal(data, &r) != nil {
		return r, ErrInvalidRequest
	}
	return r, r.Validate()
}

func (r StatusRequest) Validate() error {
	if err := r.Identity.Validate(); err != nil {
		return err
	}
	if !shortText(r.PlatformVersion) || !shortText(r.AgentVersion) {
		return ErrInvalidRequest
	}
	switch r.ServiceState {
	case "running", "stopped", "disabled", "error":
	default:
		return ErrInvalidRequest
	}
	if r.LastReconcileAt != nil {
		value := *r.LastReconcileAt
		parsed, err := time.Parse("2006-01-02T15:04:05.000000Z", value)
		if err != nil || parsed.Format("2006-01-02T15:04:05.000000Z") != value {
			return ErrInvalidRequest
		}
	}
	return nil
}

func DecodeStatus(reader io.Reader) (StatusRequest, error) {
	var r StatusRequest
	data, err := selectedLifecycle(reader, []string{"agent_protocol_version", "device_id", "platform_version", "agent_version", "service_state", "last_reconcile_success", "last_reconcile_at"}, map[string]bool{"last_reconcile_success": true, "last_reconcile_at": true})
	if err != nil || json.Unmarshal(data, &r) != nil {
		return r, ErrInvalidRequest
	}
	return r, r.Validate()
}
