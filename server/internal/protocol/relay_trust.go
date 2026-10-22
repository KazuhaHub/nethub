package protocol

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

var ErrRelayTrustVersion = errors.New("relay trust operations require protocol 1.5 or later within major 1")

func ValidateRelayTrustIdentity(identity Identity) error {
	if err := identity.Validate(); err != nil {
		return err
	}
	switch strings.SplitN(identity.AgentProtocolVersion, ".", 3)[1] {
	case "0", "1", "2", "3", "4":
		return ErrRelayTrustVersion
	}
	return nil
}

type RelayTrustGeneration struct {
	ID          string `json:"generation_id"`
	Generation  int    `json:"generation"`
	ServerName  string `json:"server_name"`
	CAPEM       string `json:"ca_pem"`
	Fingerprint string `json:"bundle_fingerprint"`
	PublishedAt string `json:"published_at"`
	NotBefore   string `json:"not_before"`
	ValidUntil  string `json:"valid_until"`
}

type RelayTrustSettings struct {
	Identity
	Desired *RelayTrustGeneration `json:"desired"`
}

type RelayTrustAppliedRequest struct {
	Identity
	GenerationID string `json:"generation_id"`
	Generation   int    `json:"generation"`
	Fingerprint  string `json:"bundle_fingerprint"`
}

type RelayTrustAppliedResponse struct {
	RelayTrustAppliedRequest
	Accepted   bool   `json:"accepted"`
	AcceptedAt string `json:"accepted_at"`
}

func (r RelayTrustAppliedRequest) Report() relaytrust.Report {
	return relaytrust.Report{GenerationID: r.GenerationID, Number: r.Generation, Fingerprint: r.Fingerprint}
}

func (r RelayTrustAppliedRequest) Validate() error {
	if err := ValidateRelayTrustIdentity(r.Identity); err != nil {
		return err
	}
	if !r.Report().Valid() {
		return ErrInvalidRequest
	}
	return nil
}

func DecodeRelayTrustSettings(reader io.Reader) (Identity, error) {
	identity, err := DecodeIdentity(reader)
	if err != nil {
		return identity, err
	}
	return identity, ValidateRelayTrustIdentity(identity)
}

func DecodeRelayTrustApplied(reader io.Reader) (RelayTrustAppliedRequest, error) {
	var r RelayTrustAppliedRequest
	data, err := selectedLifecycle(reader, []string{"agent_protocol_version", "device_id", "generation_id", "generation", "bundle_fingerprint"}, nil)
	if err != nil || json.Unmarshal(data, &r) != nil {
		return r, ErrInvalidRequest
	}
	return r, r.Validate()
}

func (r RelayTrustAppliedResponse) Validate() error {
	if err := r.RelayTrustAppliedRequest.Validate(); err != nil {
		return err
	}
	stamp, err := time.Parse(CertificateTimeLayout, r.AcceptedAt)
	if err != nil || stamp.IsZero() || stamp.Format(CertificateTimeLayout) != r.AcceptedAt || !r.Accepted {
		return ErrInvalidRequest
	}
	return nil
}
