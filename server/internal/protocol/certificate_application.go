package protocol

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

var ErrCertificateApplicationVersion = errors.New("certificate application reports require protocol 1.4 or later within major 1")

type CertificateAppliedRequest struct {
	CertificateIssuedRequest
	GenerationID    string `json:"generation_id"`
	Generation      int    `json:"generation"`
	LeafFingerprint string `json:"leaf_fingerprint"`
}

type CertificateAppliedResponse struct {
	CertificateAppliedRequest
	Accepted   bool   `json:"accepted"`
	AcceptedAt string `json:"accepted_at"`
}

func (r CertificateAppliedRequest) Validate() error {
	if err := r.Identity.Validate(); err != nil {
		return err
	}
	switch strings.SplitN(r.AgentProtocolVersion, ".", 3)[1] {
	case "0", "1", "2", "3":
		return ErrCertificateApplicationVersion
	}
	if !deviceIDPattern.MatchString(r.RequestID) || !fingerprintPattern.MatchString(r.CSRFingerprint) ||
		!deviceIDPattern.MatchString(r.GenerationID) || r.Generation < 1 || r.Generation > 2147483647 || !fingerprintPattern.MatchString(r.LeafFingerprint) {
		return ErrInvalidRequest
	}
	return nil
}

func DecodeCertificateApplied(reader io.Reader) (CertificateAppliedRequest, error) {
	var result CertificateAppliedRequest
	data, err := selectedLifecycle(reader, []string{"agent_protocol_version", "device_id", "request_id", "csr_fingerprint", "generation_id", "generation", "leaf_fingerprint"}, nil)
	if err != nil || json.Unmarshal(data, &result) != nil {
		return result, ErrInvalidRequest
	}
	return result, result.Validate()
}

func (r CertificateAppliedResponse) Validate() error {
	if r.CertificateAppliedRequest.Validate() != nil || !r.Accepted {
		return ErrInvalidRequest
	}
	stamp, err := time.Parse(CertificateTimeLayout, r.AcceptedAt)
	if err != nil || stamp.IsZero() || stamp.Format(CertificateTimeLayout) != r.AcceptedAt {
		return ErrInvalidRequest
	}
	return nil
}
