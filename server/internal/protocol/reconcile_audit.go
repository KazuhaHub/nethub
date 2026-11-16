package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

var ErrReconcileAuditVersion = errors.New("reconcile audit requires protocol 1.7 or later within major 1")

const MaxReconcileEvents = 8

type ReconcileEvent struct {
	EventID string `json:"event_id"`
	Kind    string `json:"kind"`
	Count   int64  `json:"count"`
	FirstAt string `json:"first_at"`
	LastAt  string `json:"last_at"`
}

type ReconcileAuditRequest struct {
	Identity
	Events []ReconcileEvent `json:"events"`
}

type ReconcileAuditResponse struct {
	Identity
	Accepted bool     `json:"accepted"`
	Revoked  bool     `json:"revoked"`
	EventIDs []string `json:"event_ids"`
}

func ValidateReconcileAuditIdentity(identity Identity) error {
	if err := identity.Validate(); err != nil {
		return err
	}
	switch strings.SplitN(identity.AgentProtocolVersion, ".", 3)[1] {
	case "0", "1", "2", "3", "4", "5", "6":
		return ErrReconcileAuditVersion
	}
	return nil
}

func (r ReconcileAuditRequest) Validate() error {
	if err := ValidateReconcileAuditIdentity(r.Identity); err != nil {
		return err
	}
	if len(r.Events) == 0 || len(r.Events) > MaxReconcileEvents {
		return ErrInvalidRequest
	}
	seen := make(map[string]bool, len(r.Events))
	for _, event := range r.Events {
		if !ValidRotationOperationID(event.EventID) || seen[event.EventID] || event.Count < 1 {
			return ErrInvalidRequest
		}
		seen[event.EventID] = true
		if event.Kind != "reconcile_failed" && event.Kind != "reconcile_failure_overflow" {
			return ErrInvalidRequest
		}
		if event.Kind == "reconcile_failed" && (event.Count != 1 || event.FirstAt != event.LastAt) {
			return ErrInvalidRequest
		}
		first, err := time.Parse("2006-01-02T15:04:05.000000Z", event.FirstAt)
		if err != nil || first.Year() < 1 || first.Format("2006-01-02T15:04:05.000000Z") != event.FirstAt {
			return ErrInvalidRequest
		}
		last, err := time.Parse("2006-01-02T15:04:05.000000Z", event.LastAt)
		if err != nil || last.Year() < 1 || last.Format("2006-01-02T15:04:05.000000Z") != event.LastAt || last.Before(first) {
			return ErrInvalidRequest
		}
	}
	return nil
}

func DecodeReconcileAudit(reader io.Reader) (ReconcileAuditRequest, error) {
	var result ReconcileAuditRequest
	data, err := selectedLifecycle(reader, []string{"agent_protocol_version", "device_id", "events"}, nil)
	if err != nil {
		return result, ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil {
		return result, ErrInvalidRequest
	}
	return result, result.Validate()
}
