package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

func testReconcileAudit(t *testing.T, ctx context.Context, owner, authz, web *sql.DB) {
	f := newEnrollmentFixture(t, ctx, owner, authz)
	var tenant string
	if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('Reconcile audit') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	_, token, _ := f.fresh(t, tenant)
	input := f.input
	input.EnrollToken = token
	assignment, err := f.service.Enroll(ctx, input, netip.MustParseAddr("192.0.2.131"))
	if err != nil {
		t.Fatal(err)
	}
	for _, trigger := range []string{"device_reconcile_audit", "device_reconcile_events_budget", "device_reconcile_events_immutable"} {
		if _, err = owner.ExecContext(ctx, `ALTER TABLE device_reconcile_events DISABLE TRIGGER `+trigger); err != nil {
			t.Fatal(err)
		}
		check := f.repository.Health(ctx)
		if _, err = owner.ExecContext(ctx, `ALTER TABLE device_reconcile_events ENABLE TRIGGER `+trigger); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(check, device.ErrUnavailable) {
			t.Fatal("readiness admitted disabled event guard", trigger)
		}
	}
	if err = f.repository.Health(ctx); err != nil {
		t.Fatal("restored event guards failed readiness", err)
	}
	credential, err := f.repository.DeviceCredential(ctx, assignment.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.ReconcileAuditRequest{Identity: protocol.Identity{AgentProtocolVersion: "1.7.0", DeviceID: assignment.DeviceID}, Events: []protocol.ReconcileEvent{{EventID: "11111111-1111-4111-8111-111111111111", Kind: "reconcile_failed", Count: 1, FirstAt: "2026-11-16T00:00:00.000001Z", LastAt: "2026-11-16T00:00:00.000001Z"}}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if revoked, e := f.repository.RecordReconcileEvents(ctx, credential, request); e != nil || revoked {
				t.Error("concurrent original event refused", e)
			}
		}()
	}
	wg.Wait()
	var count int
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.reconcile_failed'`, assignment.DeviceID).Scan(&count); err != nil || count != 1 {
		t.Fatal("event did not append exactly one audit", err, count)
	}
	changed := request
	changed.Events = append([]protocol.ReconcileEvent{}, request.Events...)
	changed.Events[0].FirstAt = "2026-11-16T00:00:00.000002Z"
	changed.Events[0].LastAt = changed.Events[0].FirstAt
	if _, err = f.repository.RecordReconcileEvents(ctx, credential, changed); !errors.Is(err, device.ErrReconcileAuditConflict) {
		t.Fatal("conflicting replay accepted", err)
	}
	foreign := credential
	foreign.TenantID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	if _, err = f.repository.RecordReconcileEvents(ctx, foreign, request); !errors.Is(err, device.ErrDenied) {
		t.Fatal("foreign tenant accepted", err)
	}
	if _, err = (&EnrollmentStore{DB: web}).RecordReconcileEvents(ctx, credential, request); err == nil {
		t.Fatal("Web wrote device events")
	}
	if _, err = owner.ExecContext(ctx, `CREATE FUNCTION refuse_reconcile_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('device.reconcile_failed','device.reconcile_overflow') THEN RAISE EXCEPTION 'fixture refusal'; END IF; RETURN NEW; END $$; CREATE TRIGGER refuse_reconcile_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION refuse_reconcile_audit()`); err != nil {
		t.Fatal(err)
	}
	defer owner.ExecContext(ctx, `DROP TRIGGER IF EXISTS refuse_reconcile_audit ON audit_log; DROP FUNCTION IF EXISTS refuse_reconcile_audit()`)
	newer := request
	newer.Events = append([]protocol.ReconcileEvent{}, request.Events...)
	newer.Events[0].EventID = "22222222-2222-4222-8222-222222222222"
	if _, err = f.repository.RecordReconcileEvents(ctx, credential, newer); !errors.Is(err, device.ErrUnavailable) {
		t.Fatal("audit failure ignored", err)
	}
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM device_reconcile_events WHERE device_id=$1`, assignment.DeviceID).Scan(&count); err != nil || count != 1 {
		t.Fatal("audit failure retained unacknowledged event", err, count)
	}
	if _, err = owner.ExecContext(ctx, `DROP TRIGGER refuse_reconcile_audit ON audit_log; DROP FUNCTION refuse_reconcile_audit()`); err != nil {
		t.Fatal(err)
	}
	// A revoked device may drain its retained authenticated history. This cannot
	// change revocation, restore grants or admit a tunnel.
	if _, err = owner.ExecContext(ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, assignment.DeviceID); err != nil {
		t.Fatal(err)
	}
	newer.Events[0].Kind = "reconcile_failure_overflow"
	newer.Events[0].Count = 9
	if revoked, e := f.repository.RecordReconcileEvents(ctx, credential, newer); e != nil || !revoked {
		t.Fatal("revoked history drain failed", e)
	}
	if _, err = owner.ExecContext(ctx, `UPDATE device_reconcile_events SET failure_count=2 WHERE device_id=$1`, assignment.DeviceID); err == nil {
		t.Fatal("immutable history changed")
	}
	if _, err = owner.ExecContext(ctx, `DELETE FROM device_reconcile_events WHERE device_id=$1`, assignment.DeviceID); err == nil {
		t.Fatal("immutable history deleted")
	}
	budgetTx, e := owner.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer budgetTx.Rollback()
	if _, e = budgetTx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); e != nil {
		t.Fatal(e)
	}
	if _, e = budgetTx.ExecContext(ctx, `INSERT INTO device_reconcile_events(tenant_id,device_id,event_id,kind,failure_count,first_at,last_at) SELECT $1,$2,gen_random_uuid(),'reconcile_failed',1,'2026-11-16T00:00:00Z'::timestamptz,'2026-11-16T00:00:00Z'::timestamptz FROM generate_series(1,2046)`, tenant, assignment.DeviceID); e != nil {
		t.Fatal("daily budget fixture failed", e)
	}
	if e = budgetTx.Commit(); e != nil {
		t.Fatal(e)
	}
	if _, err = f.repository.RecordReconcileEvents(ctx, credential, request); err != nil {
		t.Fatal("exhausted budget refused exact original replay", err)
	}
	limited := newer
	limited.Events = append([]protocol.ReconcileEvent{}, newer.Events...)
	limited.Events[0].EventID = "44444444-4444-4444-8444-444444444444"
	if _, err = f.repository.RecordReconcileEvents(ctx, credential, limited); !errors.Is(err, device.ErrLimited) {
		t.Fatal("distinct event exceeded daily bound", err)
	}
	if _, err = owner.ExecContext(ctx, `UPDATE devices SET device_secret_hash='replacement-fixture' WHERE id=$1`, assignment.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.repository.RecordReconcileEvents(ctx, credential, newer); !errors.Is(err, device.ErrDenied) {
		t.Fatal("stale credential replay accepted", err)
	}
	t.Log("Authenticated failure events passed eight-way exact replay, immutable conflict, tenant/Web refusal, audit rollback, revoked backlog and credential recheck")
}
