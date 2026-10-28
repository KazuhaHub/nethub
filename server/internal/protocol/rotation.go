package protocol

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

var ErrRotationVersion = errors.New("credential rotation requires protocol 1.6 or later within major 1")

var rotationIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)

// RotateRequest binds one privately journaled candidate to one rotation. The
// bearer authenticates the current credential; the operation ID alone never does.
type RotateRequest struct {
	Identity
	OperationID       string `json:"operation_id"`
	ReplacementSecret string `json:"replacement_secret"`
}

type RotateResponse struct {
	EnrollResponse
	OperationID string `json:"operation_id"`
}

func (r RotateRequest) Validate() error {
	if err := r.Identity.Validate(); err != nil {
		return err
	}
	switch strings.SplitN(r.AgentProtocolVersion, ".", 3)[1] {
	case "0", "1", "2", "3", "4", "5":
		return ErrRotationVersion
	}
	if !rotationIDPattern.MatchString(r.OperationID) || !ValidDeviceSecret(r.ReplacementSecret) {
		return ErrInvalidRequest
	}
	return nil
}

func DecodeRotate(reader io.Reader) (RotateRequest, error) {
	var result RotateRequest
	data, err := selectedLifecycle(reader, []string{"agent_protocol_version", "device_id", "operation_id", "replacement_secret"}, nil)
	if err != nil || json.Unmarshal(data, &result) != nil {
		return result, ErrInvalidRequest
	}
	return result, result.Validate()
}
