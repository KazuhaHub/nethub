package store

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/jackc/pgx/v5/pgconn"
)

// The second issued generation is administratively seeded in this disposable
// database. These cases test reporting authority, not renewal scheduling.
func testGUIApplicationReports(t *testing.T, f *enrollmentFixture, queue *GUIJobQueue, credential device.Credential, request GUIRequest, issued *guicert.IssuedCertificate, checkMetadata func(string)) guicert.ApplicationReport {
	t.Helper()
	report := guicert.ApplicationReport{DeviceID: request.DeviceID, RequestID: request.ID, RequestFingerprint: request.Fingerprint, GenerationID: issued.ID, Generation: issued.Generation, Fingerprint: issued.Fingerprint}
	if queue.Health(f.ctx) != nil {
		t.Fatal("application boundary readiness")
	}
	func() {
		if _, err := f.owner.ExecContext(f.ctx, `ALTER FUNCTION record_gui_certificate_application(uuid,uuid,text,text,uuid,integer,text) SECURITY INVOKER`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `ALTER FUNCTION record_gui_certificate_application(uuid,uuid,text,text,uuid,integer,text) SECURITY DEFINER`); err != nil {
				t.Error(err)
			}
		}()
		if queue.Health(f.ctx) == nil {
			t.Fatal("changed application function accepted")
		}
	}()
	func() {
		if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE gui_certificate_applications DISABLE TRIGGER gui_certificate_application_immutable`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE gui_certificate_applications ENABLE TRIGGER gui_certificate_application_immutable`); err != nil {
				t.Error(err)
			}
		}()
		if queue.Health(f.ctx) == nil {
			t.Fatal("disabled application immutability accepted")
		}
	}()
	// Fail the audit after the report INSERT; both must roll back together.
	func() {
		if _, err := f.owner.ExecContext(f.ctx, `CREATE FUNCTION fixture_gui_application_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='device.certificate_applied' THEN RAISE EXCEPTION 'Fixture audit failure'; END IF; RETURN NEW; END $$`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `DROP FUNCTION fixture_gui_application_audit_failure()`); err != nil {
				t.Error(err)
			}
		}()
		if _, err := f.owner.ExecContext(f.ctx, `CREATE TRIGGER fixture_gui_application_audit_failure BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fixture_gui_application_audit_failure()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `DROP TRIGGER fixture_gui_application_audit_failure ON audit_log`); err != nil {
				t.Error(err)
			}
		}()
		if _, err := queue.Acknowledge(f.ctx, credential, report); !errors.Is(err, device.ErrUnavailable) {
			t.Fatal("audit failure acknowledged", err)
		}
		var count int
		if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM gui_certificate_applications WHERE device_id=$1`, request.DeviceID).Scan(&count); err != nil || count != 0 {
			t.Fatal("audit failure left a report", err)
		}
	}()
	first, err := queue.Acknowledge(f.ctx, credential, report)
	if err != nil || first.IsZero() {
		t.Fatal("valid application denied", err)
	}
	checkMetadata("applied")
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			stamp, err := queue.Acknowledge(f.ctx, credential, report)
			if err == nil && !stamp.Equal(first) {
				err = errors.New("confirmation timestamp changed")
			}
			results <- err
		})
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("duplicate report failed", err)
		}
	}
	for _, change := range []func(*guicert.ApplicationReport){func(v *guicert.ApplicationReport) { v.RequestID = "00000000-0000-0000-0000-000000000000" }, func(v *guicert.ApplicationReport) { v.RequestFingerprint = strings.Repeat("0", 64) }, func(v *guicert.ApplicationReport) { v.GenerationID = "00000000-0000-0000-0000-000000000000" }, func(v *guicert.ApplicationReport) { v.Generation++ }, func(v *guicert.ApplicationReport) { v.Fingerprint = strings.Repeat("0", 64) }} {
		changed := report
		change(&changed)
		if _, err := queue.Acknowledge(f.ctx, credential, changed); !errors.Is(err, device.ErrDenied) {
			t.Fatal("changed generation binding acknowledged", err)
		}
	}
	for _, wrong := range []device.Credential{{TenantID: "00000000-0000-0000-0000-000000000000", Hash: credential.Hash}, {TenantID: credential.TenantID, Hash: credential.Hash + "changed"}} {
		if _, err := queue.Acknowledge(f.ctx, wrong, report); !errors.Is(err, device.ErrDenied) {
			t.Fatal("foreign/stale credential acknowledged", err)
		}
	}
	var secondJob, secondID string
	if err := f.owner.QueryRowContext(f.ctx, `INSERT INTO gui_certificate_jobs(tenant_id,device_id,request_id,generation,state) SELECT tenant_id,device_id,request_id,2,'issued' FROM gui_certificate_generations WHERE id=$1 RETURNING id`, issued.ID).Scan(&secondJob); err != nil {
		t.Fatal("disposable second generation job", err)
	}
	checkMetadata("renewing")
	if err := f.owner.QueryRowContext(f.ctx, `INSERT INTO gui_certificate_generations(tenant_id,device_id,request_id,job_id,generation,chain_pem,leaf_fingerprint,not_before,not_after,valid_until,renew_after,completed_lease,completed_version) SELECT tenant_id,device_id,request_id,$2,2,chain_pem,leaf_fingerprint,not_before,not_after,valid_until,renew_after,gen_random_uuid(),1 FROM gui_certificate_generations WHERE id=$1 RETURNING id`, issued.ID, secondJob).Scan(&secondID); err != nil {
		t.Fatal("disposable second generation material", err)
	}
	if stamp, err := queue.Acknowledge(f.ctx, credential, report); err != nil || !stamp.Equal(first) {
		t.Fatal("new issuance invalidated a still-valid installed generation", err)
	}
	latest := report
	latest.GenerationID = secondID
	latest.Generation = 2
	if _, err := queue.Acknowledge(f.ctx, credential, latest); err != nil {
		t.Fatal("new generation report failed", err)
	}
	if _, err := queue.Acknowledge(f.ctx, credential, report); !errors.Is(err, device.ErrDenied) {
		t.Fatal("confirmed generation regressed", err)
	}
	var reports, audits int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT (SELECT count(*) FROM gui_certificate_applications WHERE device_id=$1),(SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.certificate_applied')`, request.DeviceID).Scan(&reports, &audits); err != nil || reports != 2 || audits != 2 {
		t.Fatal("report/audit idempotence failed", err)
	}
	for _, statement := range []string{`UPDATE gui_certificate_applications SET accepted_at=clock_timestamp() WHERE generation_id=$1`, `DELETE FROM gui_certificate_applications WHERE generation_id=$1`} {
		_, err := f.owner.ExecContext(f.ctx, statement, issued.ID)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "P0001" {
			t.Fatal("application evidence mutated", err)
		}
	}
	for _, role := range []string{"nethub_web", "nethub_authz", "nethub_issuer"} {
		var allowed bool
		if err := f.owner.QueryRowContext(f.ctx, `SELECT has_table_privilege($1,'public.gui_certificate_applications','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege($1,'public.gui_certificate_applications','SELECT,INSERT,UPDATE,REFERENCES')`, role).Scan(&allowed); err != nil || allowed {
			t.Fatal("raw report access exposed", err)
		}
	}
	for _, role := range []string{"nethub_web", "nethub_issuer"} {
		var allowed bool
		if err := f.owner.QueryRowContext(f.ctx, `SELECT has_function_privilege($1,'public.record_gui_certificate_application(uuid,uuid,text,text,uuid,integer,text)','EXECUTE')`, role).Scan(&allowed); err != nil || allowed {
			t.Fatal("reporting authority exposed", err)
		}
	}
	t.Log("Authenticated application reports passed atomic audit rollback, eight concurrent identical receipts, immutable history/private grants, current-credential binding, valid superseded issuance and monotonic applied generations; second-generation rows were administratively seeded")
	return latest
}

func testRevocationFencesGUIApplication(t *testing.T, f *enrollmentFixture, queue *GUIJobQueue, credential device.Credential, report guicert.ApplicationReport) {
	t.Helper()
	tx, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(f.ctx, `SELECT 1 FROM devices WHERE id=$1 FOR UPDATE`, report.DeviceID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := queue.Acknowledge(f.ctx, credential, report); result <- err }()
	select {
	case err := <-result:
		t.Fatal("report bypassed the assignment lock", err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, err = tx.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, report.DeviceID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, device.ErrDenied) {
			t.Fatal("revocation lost to a stale authenticated report", err)
		}
	case <-f.ctx.Done():
		t.Fatal("application lock did not finish")
	}
	t.Log("A report blocked on the live assignment lock was denied after revocation committed")
}
