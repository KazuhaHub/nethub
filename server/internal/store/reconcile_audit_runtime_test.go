package store

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

func testRuntimeReconcileAudit(t *testing.T, f *enrollmentFixture, client *http.Client, address string, assignment protocol.EnrollResponse) {
	t.Helper()
	input := protocol.ReconcileAuditRequest{Identity: protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: assignment.DeviceID}, Events: []protocol.ReconcileEvent{{EventID: "33333333-3333-4333-8333-333333333333", Kind: "reconcile_failed", Count: 1, FirstAt: "2026-11-16T00:00:00.000001Z", LastAt: "2026-11-16T00:00:00.000001Z"}}}
	send := func(input protocol.ReconcileAuditRequest, secret string) (int, protocol.ReconcileAuditResponse) {
		t.Helper()
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(f.ctx, http.MethodPost, "http://"+address+"/api/v1/devices/reconcile-events", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "console.example.com"
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+secret)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("compiled reconcile request failed")
		}
		defer response.Body.Close()
		var result protocol.ReconcileAuditResponse
		if response.StatusCode == 200 {
			if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&result) != nil {
				t.Fatal("invalid reconcile acknowledgement")
			}
		}
		return response.StatusCode, result
	}
	for range 2 {
		status, result := send(input, assignment.DeviceSecret)
		if status != 200 || !result.Accepted || result.Revoked || result.DeviceID != assignment.DeviceID || len(result.EventIDs) != 1 || result.EventIDs[0] != input.Events[0].EventID {
			t.Fatal("compiled exact replay failed", status)
		}
	}
	if status, _ := send(input, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); status != 401 {
		t.Fatal("invalid credential admitted", status)
	}
	input.Events[0].FirstAt = "2026-11-16T00:00:00.000002Z"
	input.Events[0].LastAt = input.Events[0].FirstAt
	if status, _ := send(input, assignment.DeviceSecret); status != 409 {
		t.Fatal("compiled conflict admitted", status)
	}
	var count int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.reconcile_failed'`, assignment.DeviceID).Scan(&count); err != nil || count != 1 {
		t.Fatal("compiled event audit missing or duplicated", err, count)
	}
	t.Log("Compiled authz failure-event endpoint authenticated original delivery, exact lost-reply replay, one audit and conflicting-content refusal")
}
