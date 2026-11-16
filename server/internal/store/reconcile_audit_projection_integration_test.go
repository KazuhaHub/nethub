package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func testReconcileAuditProjection(t *testing.T, ctx context.Context, owner, authz, webDB *sql.DB) {
	t.Helper()
	f := newEnrollmentFixture(t, ctx, owner, authz)
	var tenant string
	if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('Failure projection fixture') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	_, token, actor := f.fresh(t, tenant)
	input := f.input
	input.EnrollToken = token
	assignment, err := f.service.Enroll(ctx, input, netip.MustParseAddr("192.0.2.132"))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := f.repository.DeviceCredential(ctx, assignment.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.ReconcileAuditRequest{Identity: protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: assignment.DeviceID}, Events: []protocol.ReconcileEvent{
		{EventID: "55555555-5555-4555-8555-555555555555", Kind: "reconcile_failed", Count: 1, FirstAt: "2026-11-16T00:00:00.000001Z", LastAt: "2026-11-16T00:00:00.000001Z"},
		{EventID: "66666666-6666-4666-8666-666666666666", Kind: "reconcile_failure_overflow", Count: 9223372036854775807, FirstAt: "2026-11-16T00:00:00.000001Z", LastAt: "2026-11-16T00:00:00.000002Z"},
	}}
	if revoked, err := f.repository.RecordReconcileEvents(ctx, credential, request); err != nil || revoked {
		t.Fatal("actual event ingestion failed", err)
	}
	repo := &ConsoleStore{AuthStore: AuthStore{DB: webDB, Tenant: tenant}}
	read := func(action string) web.AuditPage {
		t.Helper()
		page, err := repo.Audit(ctx, actor, web.AuditQuery{Limit: 200, DeviceID: assignment.DeviceID, Action: action})
		if err != nil {
			t.Fatal("actual Web audit query failed", err)
		}
		data, err := json.Marshal(page)
		if err != nil || strings.Contains(string(data), "projection-private-sentinel") || strings.Contains(string(data), "event_id") {
			t.Fatal("audit details escaped the narrow projection", err)
		}
		return page
	}
	check := func(action, count, last string) {
		t.Helper()
		page := read(action)
		if len(page.Items) != 1 {
			t.Fatal("actual Web audit omitted the original event")
		}
		d := page.Items[0].Details
		if d.FailureCount == nil || *d.FailureCount != count || d.DeviceReported == nil || !*d.DeviceReported || d.FirstReportedAt == nil || d.LastReportedAt == nil {
			t.Fatal("actual Web audit omitted typed reconcile failure details")
		}
		if d.FirstReportedAt.UTC().Format("2006-01-02T15:04:05.000000Z") != request.Events[0].FirstAt || d.LastReportedAt.UTC().Format("2006-01-02T15:04:05.000000Z") != last {
			t.Fatal("actual Web audit changed device-reported timestamp precision")
		}
	}
	check("device.reconcile_failed", "1", request.Events[0].LastAt)
	check("device.reconcile_overflow", "9223372036854775807", request.Events[1].LastAt)
	// A large unrelated field must be excluded in SQL, rather than selecting the
	// whole payload and causing the bounded decoder to drop otherwise valid data.
	tx, err := owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"device.reconcile_failed", "device.fixture"} {
		if _, err = tx.ExecContext(ctx, `SELECT append_audit('device',$1,$2,$1,jsonb_build_object(
 'failure_count',1,'device_reported',true,'first_reported_at','2026-11-16T00:00:00.000001Z',
 'last_reported_at','2026-11-16T00:00:00.000001Z','private',repeat('projection-private-sentinel',100)))`, assignment.DeviceID, action); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	page := read("device.reconcile_failed")
	if len(page.Items) != 2 {
		t.Fatal("narrow projection lost an audit row")
	}
	for _, entry := range page.Items {
		if entry.Details.FailureCount == nil || *entry.Details.FailureCount != "1" {
			t.Fatal("unrelated payload bytes erased valid typed details")
		}
	}
	other := read("device.fixture")
	if len(other.Items) != 1 || other.Items[0].Details.FailureCount != nil || other.Items[0].Details.DeviceReported != nil {
		t.Fatal("unrelated audit action acquired reconcile detail authority")
	}
	t.Log("Actual Web role selected ordinary and exact int64-overflow failure details without raw payloads or unrelated-action enrichment")
}
