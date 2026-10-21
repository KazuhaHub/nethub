// Package protocol defines the platform-neutral device wire types.
package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
)

const Version = "1.2.0"
const MaxBodyBytes = boundedjson.MaxBytes

var ErrInvalidRequest = errors.New("invalid device request")
var ErrIncompatibleVersion = errors.New("unsupported device protocol; supported major is 1")

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
var platformPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
var capabilityPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$`)

type EnrollRequest struct {
	AgentProtocolVersion string   `json:"agent_protocol_version"`
	EnrollToken          string   `json:"enroll_token"`
	Platform             string   `json:"platform"`
	PlatformVersion      string   `json:"platform_version"`
	AgentVersion         string   `json:"agent_version"`
	Capabilities         []string `json:"capabilities"`
	Hostname             string   `json:"hostname"`
	ClusterHint          bool     `json:"cluster_hint"`
	GUIPublicKey         string   `json:"gui_public_key,omitempty"`
}

type EnrollResponse struct {
	AgentProtocolVersion string `json:"agent_protocol_version"`
	DeviceID             string `json:"device_id"`
	DeviceSecret         string `json:"device_secret"`
	FRPToken             string `json:"frp_token"`
	ServerAddr           string `json:"server_addr"`
	ServerPort           uint16 `json:"server_port"`
	ServerName           string `json:"server_name"`
	Subdomain            string `json:"subdomain"`
	DomainClaim          string `json:"domain_claim"`
	RelayCAPEM           string `json:"relay_ca_pem"`
	GUIKeyFingerprint    string `json:"gui_key_fingerprint,omitempty"`
}

// CompatibleVersion checks the major before any enrollment token is consumed.
func CompatibleVersion(value string) error {
	if len(value) > 64 || !versionPattern.MatchString(value) {
		return ErrInvalidRequest
	}
	if strings.SplitN(value, ".", 2)[0] != "1" {
		return ErrIncompatibleVersion
	}
	return nil
}

func shortText(value string) bool {
	if len(value) > 128 {
		return false
	}
	for _, c := range value {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func (r EnrollRequest) Validate() error {
	if err := r.ValidateMetadata(); err != nil {
		return err
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(r.EnrollToken)
	if err != nil || len(token) != 32 || len(r.EnrollToken) != 43 {
		return ErrInvalidRequest
	}
	return nil
}

// ValidateMetadata also serves the token-free registration record after admission.
func (r EnrollRequest) ValidateMetadata() error {
	if err := CompatibleVersion(r.AgentProtocolVersion); err != nil {
		return err
	}
	if !platformPattern.MatchString(r.Platform) || len(r.Hostname) > 253 ||
		!hostnamePattern.MatchString(r.Hostname) || !shortText(r.PlatformVersion) ||
		!shortText(r.AgentVersion) || len(r.Capabilities) < 1 || len(r.Capabilities) > 16 {
		return ErrInvalidRequest
	}
	if r.GUIPublicKey != "" {
		if _, err := guicert.ValidatePublicKey(r.GUIPublicKey); err != nil {
			return ErrInvalidRequest
		}
	}
	seen := make(map[string]bool, len(r.Capabilities))
	for _, capability := range r.Capabilities {
		if len(capability) > 64 || !capabilityPattern.MatchString(capability) || seen[capability] {
			return ErrInvalidRequest
		}
		seen[capability] = true
	}
	return nil
}

// DecodeEnroll retains only known fields; optional extensions never become settings.
func DecodeEnroll(reader io.Reader) (EnrollRequest, error) {
	var request EnrollRequest
	fields, err := boundedjson.Object(reader)
	if err != nil || len(fields) > 24 {
		return request, ErrInvalidRequest
	}
	known := make(map[string]json.RawMessage, 8)
	for _, field := range []string{"agent_protocol_version", "enroll_token", "platform", "platform_version", "agent_version", "capabilities", "hostname", "cluster_hint"} {
		value, ok := fields[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return request, ErrInvalidRequest
		}
		known[field] = value
	}
	if value, ok := fields["gui_public_key"]; ok {
		var key string
		if json.Unmarshal(value, &key) != nil || key == "" {
			return EnrollRequest{}, ErrInvalidRequest
		}
		known["gui_public_key"] = value
	}
	filtered, err := json.Marshal(known)
	if err != nil || json.Unmarshal(filtered, &request) != nil {
		return EnrollRequest{}, ErrInvalidRequest
	}
	if err := request.Validate(); err != nil {
		return EnrollRequest{}, err
	}
	return request, nil
}
