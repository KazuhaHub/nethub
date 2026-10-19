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
	"unicode/utf8"
)

const Version = "1.0.0"
const MaxBodyBytes = 65536

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
	seen := make(map[string]bool, len(r.Capabilities))
	for _, capability := range r.Capabilities {
		if len(capability) > 64 || !capabilityPattern.MatchString(capability) || seen[capability] {
			return ErrInvalidRequest
		}
		seen[capability] = true
	}
	return nil
}

// checkJSON rejects duplicate keys even in extensions, with a bounded nesting depth.
func checkJSON(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrInvalidRequest
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidRequest
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] || len(seen) >= 64 {
				return ErrInvalidRequest
			}
			seen[name] = true
			if err := checkJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for count := 0; decoder.More(); count++ {
			if count >= 256 {
				return ErrInvalidRequest
			}
			if err := checkJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidRequest
	}
	if _, err := decoder.Token(); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

// DecodeEnroll retains only known fields; optional extensions never become settings.
func DecodeEnroll(reader io.Reader) (EnrollRequest, error) {
	var request EnrollRequest
	data, err := io.ReadAll(io.LimitReader(reader, MaxBodyBytes+1))
	if err != nil || len(data) > MaxBodyBytes || !utf8.Valid(data) || !json.Valid(data) {
		return request, ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := checkJSON(decoder, 0); err != nil {
		return request, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) > 24 {
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
	filtered, err := json.Marshal(known)
	if err != nil || json.Unmarshal(filtered, &request) != nil {
		return EnrollRequest{}, ErrInvalidRequest
	}
	if err := request.Validate(); err != nil {
		return EnrollRequest{}, err
	}
	return request, nil
}
