package store

import (
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/relayhook"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"github.com/jackc/pgx/v5/pgconn"
)

func testDisconnectRequests(t *testing.T, f *enrollmentFixture, webRole *sql.DB, tenant, otherTenant string) {
	t.Helper()
	makeDevice := func(scope string) (string, string) {
		r, _, actor := f.fresh(t, scope)
		assignment, err := f.repository.Register(f.ctx, r, f.issue)
		if err != nil {
			t.Fatal(err)
		}
		return assignment.ID, actor
	}
	id, actor := makeDevice(tenant)
	other, otherActor := makeDevice(tenant)
	foreign, _ := makeDevice(otherTenant)
	repo := &ConsoleStore{AuthStore: AuthStore{DB: webRole, Tenant: tenant}}
	ip := netip.MustParseAddr("192.0.2.177")
	for _, target := range []string{other, foreign, "00000000-0000-0000-0000-000000000000"} {
		if _, err := repo.RequestDisconnect(f.ctx, actor, target, ip); !errors.Is(err, web.ErrDeviceUnavailable) {
			t.Fatal("foreign request exposed or accepted", err)
		}
	}
	if _, err := repo.RequestDisconnect(f.ctx, actor, id, ip); !errors.Is(err, web.ErrDeviceNotRevoked) {
		t.Fatal("active device received cutoff request", err)
	}
	for _, target := range []string{id, foreign} {
		tx, err := webRole.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.ExecContext(f.ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(f.ctx, `SELECT request_device_disconnect($1,$2)`, actor, target)
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatal("narrow helper admitted active or foreign device", err)
		}
		tx.Rollback()
	}
	cache, err := relayhook.NewRevocationCache(&RelayStore{DB: f.repository.DB}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil || cache.Refresh(f.ctx) != nil {
		t.Fatal("initial memory cache failed", err)
	}
	if _, err = repo.RevokeDevice(f.ctx, actor, id, ip); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan web.DeviceDisconnect, 8)
	failures := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			result, err := repo.RequestDisconnect(f.ctx, actor, id, ip)
			results <- result
			failures <- err
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("concurrent request failed", err)
		}
	}
	var first web.DeviceDisconnect
	for result := range results {
		if result.State != "pending" || result.ArmedAt != nil {
			t.Fatal("request prematurely armed")
		}
		if first.RequestID == "" {
			first = result
		}
		if result.RequestID != first.RequestID || !result.RequestedAt.Equal(first.RequestedAt) {
			t.Fatal("retry changed immutable request")
		}
	}
	counts := func() (int, int) {
		var requests, audits int
		if err := f.owner.QueryRowContext(f.ctx, `SELECT (SELECT count(*) FROM device_disconnect_requests WHERE device_id=$1),(SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.disconnect_requested')`, id).Scan(&requests, &audits); err != nil {
			t.Fatal(err)
		}
		return requests, audits
	}
	if requests, audits := counts(); requests != 1 || audits != 1 {
		t.Fatal("concurrent request duplicated row or audit")
	}
	if cache.ProcessDisconnects(f.ctx) != nil {
		t.Fatal("initial queue processing failed")
	}
	pending, err := repo.RequestDisconnect(f.ctx, actor, id, ip)
	if err != nil || pending.State != "pending" {
		t.Fatal("database revocation acknowledged before cache publication", err)
	}
	if cache.Refresh(f.ctx) != nil {
		t.Fatal("denial publication failed")
	}
	// A real audit failure must retain pending status even after memory publication.
	if _, err = f.owner.ExecContext(f.ctx, `CREATE FUNCTION reject_disconnect_armed_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='device.disconnect_armed' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$;
CREATE TRIGGER reject_disconnect_armed_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_disconnect_armed_audit()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := f.owner.ExecContext(f.ctx, `DROP TRIGGER IF EXISTS reject_disconnect_armed_audit ON audit_log; DROP FUNCTION IF EXISTS reject_disconnect_armed_audit()`); err != nil {
			t.Error(err)
		}
	}()
	if cache.ProcessDisconnects(f.ctx) == nil {
		t.Fatal("armed audit failure returned success")
	}
	if _, err = f.owner.ExecContext(f.ctx, `DROP TRIGGER reject_disconnect_armed_audit ON audit_log; DROP FUNCTION reject_disconnect_armed_audit()`); err != nil {
		t.Fatal(err)
	}
	pending, err = repo.RequestDisconnect(f.ctx, actor, id, ip)
	if err != nil || pending.State != "pending" {
		t.Fatal("armed audit failure committed receipt", err)
	}
	if cache.ProcessDisconnects(f.ctx) != nil {
		t.Fatal("retry did not arm request")
	}
	armed, err := repo.RequestDisconnect(f.ctx, actor, id, ip)
	if err != nil || armed.State != "armed" || armed.ArmedAt == nil || armed.RequestID != first.RequestID {
		t.Fatal("armed receipt missing", err)
	}
	if cache.ProcessDisconnects(f.ctx) != nil {
		t.Fatal("processed retry failed")
	}
	again, err := repo.RequestDisconnect(f.ctx, actor, id, ip)
	if err != nil || !again.ArmedAt.Equal(*armed.ArmedAt) {
		t.Fatal("first armed timestamp changed", err)
	}
	var armedAudits int
	if err = f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.disconnect_armed'`, id).Scan(&armedAudits); err != nil || armedAudits != 1 {
		t.Fatal("armed audit not idempotent", err)
	}
	for _, role := range []string{"nethub_web", "nethub_authz"} {
		var broad bool
		if err = f.owner.QueryRowContext(f.ctx, `SELECT has_table_privilege($1,'public.device_disconnect_requests','INSERT,DELETE,TRUNCATE') OR has_column_privilege($1,'public.device_disconnect_requests','device_id','UPDATE')`, role).Scan(&broad); err != nil || broad {
			t.Fatal("queue role got identity or destructive authority", err)
		}
	}
	if _, err = repo.RevokeDevice(f.ctx, otherActor, other, ip); err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.ExecContext(f.ctx, `UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1`, otherActor); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.RequestDisconnect(f.ctx, otherActor, other, ip); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("disabled actor requested cutoff", err)
	}
	page, err := repo.Devices(f.ctx, actor, web.DeviceQuery{Limit: 200})
	if err != nil {
		t.Fatal("disconnect projection failed", err)
	}
	found := false
	for _, device := range page.Items {
		if device.ID == id {
			found = device.Disconnect != nil && device.Disconnect.State == "armed"
		}
	}
	if !found {
		t.Fatal("scoped inventory omitted armed receipt")
	}
	if armed.ArmedAt.Before(first.RequestedAt.Add(-time.Second)) {
		t.Fatal("armed time preceded request")
	}
	processing, err := f.repository.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = processing.ExecContext(f.ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	_, err = processing.ExecContext(f.ctx, `UPDATE device_disconnect_requests SET processed_at=NULL WHERE id=$1`, first.RequestID)
	var immutable *pgconn.PgError
	if !errors.As(err, &immutable) || immutable.Code != "23514" {
		t.Fatal("authz could erase first armed receipt", err)
	}
	processing.Rollback()
	if _, err = f.owner.ExecContext(f.ctx, `UPDATE users SET role='admin' WHERE id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.RequestDisconnect(f.ctx, actor, other, ip); err != nil {
		t.Fatal("enabled tenant admin could not request another owner's revoked device", err)
	}
	t.Log("Disconnect requests passed revoked-only owner/tenant scope, eight exact retries with one request/audit, publication-before-ack, armed audit rollback, stable receipt, narrow role grants and scoped inventory status")
}
