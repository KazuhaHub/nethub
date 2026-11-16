package protocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func auditRequest() ReconcileAuditRequest {
	return ReconcileAuditRequest{Identity: Identity{AgentProtocolVersion: "1.7.0", DeviceID: "11111111-1111-4111-8111-111111111111"}, Events: []ReconcileEvent{{EventID: "22222222-2222-4222-8222-222222222222", Kind: "reconcile_failed", Count: 1, FirstAt: "2026-11-16T00:00:00.000001Z", LastAt: "2026-11-16T00:00:00.000001Z"}}}
}

func TestReconcileAuditBoundsAndIdentity(t *testing.T) {
	for _, version := range []string{"1.7.0", "1.8.0-rc.1", "1.999999999999999999999.0"} {
		r := auditRequest()
		r.AgentProtocolVersion = version
		if err := r.Validate(); err != nil {
			t.Fatal(version, err)
		}
	}
	for _, version := range []string{"1.0.0", "1.6.0", "1.6.999"} {
		r := auditRequest()
		r.AgentProtocolVersion = version
		if !errors.Is(r.Validate(), ErrReconcileAuditVersion) {
			t.Fatal("old minor admitted")
		}
	}
	cases := map[string]func(*ReconcileAuditRequest){
		"empty":                  func(r *ReconcileAuditRequest) { r.Events = nil },
		"oversized":              func(r *ReconcileAuditRequest) { r.Events = make([]ReconcileEvent, 9) },
		"duplicate":              func(r *ReconcileAuditRequest) { r.Events = append(r.Events, r.Events[0]) },
		"unknown kind":           func(r *ReconcileAuditRequest) { r.Events[0].Kind = "private diagnostic" },
		"zero count":             func(r *ReconcileAuditRequest) { r.Events[0].Count = 0 },
		"nonaggregate count":     func(r *ReconcileAuditRequest) { r.Events[0].Count = 2 },
		"noncanonical timestamp": func(r *ReconcileAuditRequest) { r.Events[0].FirstAt = "2026-11-16T00:00:00Z" },
		"nonexistent date":       func(r *ReconcileAuditRequest) { r.Events[0].FirstAt = "2026-02-30T00:00:00.000000Z" },
		"zero year":              func(r *ReconcileAuditRequest) { r.Events[0].FirstAt = "0000-01-01T00:00:00.000000Z" },
		"zero id":                func(r *ReconcileAuditRequest) { r.Events[0].EventID = "00000000-0000-0000-0000-000000000000" },
		"reversed interval": func(r *ReconcileAuditRequest) {
			r.Events[0].Kind = "reconcile_failure_overflow"
			r.Events[0].FirstAt = "2026-11-17T00:00:00.000000Z"
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := auditRequest()
			change(&r)
			if r.Validate() == nil {
				t.Fatal("invalid event admitted")
			}
		})
	}
	r := auditRequest()
	r.Events[0].Kind = "reconcile_failure_overflow"
	r.Events[0].Count = 9223372036854775807
	if r.Validate() != nil {
		t.Fatal("bounded overflow summary refused")
	}
}

func TestReconcileAuditStrictWire(t *testing.T) {
	raw, _ := json.Marshal(auditRequest())
	if _, err := DecodeReconcileAudit(strings.NewReader(string(raw))); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(string(raw), `"count":1`, `"count":null`, 1),
		strings.Replace(string(raw), `"count":1`, `"count":true`, 1),
		strings.Replace(string(raw), `"count":1`, `"count":1,"count":1`, 1),
		strings.Replace(string(raw), `"count":1`, `"count":1,"diagnostic":"secret"`, 1),
		strings.Replace(string(raw), `"count":1`, `"count":9223372036854775808`, 1),
		string(raw) + `{}`,
	} {
		if _, err := DecodeReconcileAudit(strings.NewReader(raw)); err == nil {
			t.Fatal("malformed wire admitted")
		}
	}
}
