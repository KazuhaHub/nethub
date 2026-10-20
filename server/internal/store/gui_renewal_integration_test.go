package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/jackc/pgx/v5/pgconn"
)

// Only scheduling authority is tested here: generation one's public material
// and clock metadata are administratively seeded in this disposable database.
// Real second-generation issuance and native application need separate evidence.
func testGUIRenewalAdmission(t *testing.T, f *enrollmentFixture, web *sql.DB, tenant string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	r, _, _ := f.fresh(t, tenant)
	r.GUIPublicKey = base64.RawURLEncoding.EncodeToString(spki)
	a, err := f.repository.Register(f.ctx, r, f.issue)
	if err != nil {
		t.Fatal(err)
	}
	requests := &GUIRequestStore{Enrollment: f.repository, DeviceDomain: "renewal.example.com"}
	queue := &GUIJobQueue{Requests: requests}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{a.Subdomain + ".renewal.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	credential := device.Credential{TenantID: tenant, Hash: r.SecretHash}
	request, err := queue.Admit(f.ctx, credential, a.ID, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	if err != nil {
		t.Fatal(err)
	}
	job, err := queue.Enqueue(f.ctx, credential, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE gui_certificate_jobs SET state='issued' WHERE id=$1`, job); err != nil {
		t.Fatal(err)
	}
	var generation string
	err = f.owner.QueryRowContext(f.ctx, `INSERT INTO gui_certificate_generations(tenant_id,device_id,request_id,job_id,generation,chain_pem,leaf_fingerprint,not_before,not_after,valid_until,renew_after,completed_lease,completed_version)
 VALUES($1,$2,$3,$4,1,'public scheduling fixture',$5,statement_timestamp()-interval '1 day',statement_timestamp()+interval '90 days',statement_timestamp()+interval '90 days',statement_timestamp()+interval '60 days',gen_random_uuid(),1) RETURNING id`, tenant, a.ID, request.ID, job, strings.Repeat("a", 64)).Scan(&generation)
	if err != nil {
		t.Fatal(err)
	}
	adapter := &guiissuer.SQLStore{Run: issuerSQLInput, Domain: "renewal.example.com", AllowsURL: func(string) bool { return true }}
	if err := adapter.Ready(f.ctx); err != nil {
		t.Fatal("renewal schema readiness", err)
	}
	if n, err := adapter.EnqueueRenewals(f.ctx); err != nil || n != 0 {
		t.Fatal("early renewal queued", n, err)
	}
	// Age only fixture metadata, transactionally restoring its immutable trigger.
	tx, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range []string{`ALTER TABLE gui_certificate_generations DISABLE TRIGGER gui_certificate_generation_immutable`,
		`UPDATE gui_certificate_generations SET issued_at=clock_timestamp()-interval '2 days',renew_after=clock_timestamp()-interval '1 day' WHERE id=$1`,
		`ALTER TABLE gui_certificate_generations ENABLE TRIGGER gui_certificate_generation_immutable`} {
		args := []any{}
		if strings.Contains(statement, "$1") {
			args = append(args, generation)
		}
		if _, err := tx.ExecContext(f.ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, db := range []*sql.DB{f.owner, web, f.repository.DB} {
		_, err := db.ExecContext(f.ctx, `SELECT enqueue_due_gui_certificate_renewals('renewal.example.com','[]')`)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatal("non-issuer scheduled renewal", err)
		}
	}
	adapter.Excluded = []string{a.Subdomain + ".renewal.example.com"}
	if n, err := adapter.EnqueueRenewals(f.ctx); err != nil || n != 0 {
		t.Fatal("excluded host queued", n, err)
	}
	adapter.Excluded = nil
	adapter.Domain = "other.example.com"
	if n, err := adapter.EnqueueRenewals(f.ctx); err != nil || n != 0 {
		t.Fatal("foreign deployment queued", n, err)
	}
	adapter.Domain = "renewal.example.com"
	locked, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Rollback()
	if _, err := locked.ExecContext(f.ctx, `SELECT id FROM devices WHERE id=$1 FOR UPDATE`, a.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := adapter.EnqueueRenewals(f.ctx); err != nil || n != 0 {
		t.Fatal("busy parent not skipped", n, err)
	}
	if err := locked.Rollback(); err != nil {
		t.Fatal(err)
	}
	func() {
		if _, err := f.owner.ExecContext(f.ctx, `CREATE FUNCTION fixture_gui_renewal_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='device.certificate_renewal_queued' THEN RAISE EXCEPTION 'Fixture audit failure'; END IF; RETURN NEW; END $$`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `DROP FUNCTION fixture_gui_renewal_audit_failure()`); err != nil {
				t.Error(err)
			}
		}()
		if _, err := f.owner.ExecContext(f.ctx, `CREATE TRIGGER fixture_gui_renewal_audit_failure BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fixture_gui_renewal_audit_failure()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `DROP TRIGGER fixture_gui_renewal_audit_failure ON audit_log`); err != nil {
				t.Error(err)
			}
		}()
		if _, err := adapter.EnqueueRenewals(f.ctx); err != guiissuer.ErrDatabase {
			t.Fatal("renewal audit failure accepted", err)
		}
		var count int
		if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM gui_certificate_jobs WHERE device_id=$1 AND generation>1`, a.ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed audit left new work", err)
		}
	}()
	var wg sync.WaitGroup
	results := make(chan error, 8)
	counts := make(chan int, 8)
	for range 8 {
		wg.Go(func() { n, err := adapter.EnqueueRenewals(f.ctx); results <- err; counts <- n })
	}
	wg.Wait()
	close(results)
	close(counts)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent renewal", err)
		}
	}
	total := 0
	for n := range counts {
		total += n
	}
	if total != 1 {
		t.Fatal("concurrent renewal was not deduplicated", total)
	}
	var nextJob string
	var number int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT id,generation FROM gui_certificate_jobs WHERE device_id=$1 AND generation=2`, a.ID).Scan(&nextJob, &number); err != nil || number != 2 {
		t.Fatal("next generation missing", err)
	}
	if retry, err := queue.Enqueue(f.ctx, credential, a.ID); err != nil || retry != job {
		t.Fatal("admission retry did not retain generation one", err)
	}
	if n, err := adapter.EnqueueRenewals(f.ctx); err != nil || n != 0 {
		t.Fatal("active job duplicated", n, err)
	}
	claimed, err := adapter.Claim(f.ctx)
	if err != nil || claimed == nil || claimed.Lease.ID != nextJob || claimed.Lease.Generation != 2 ||
		claimed.Lease.RequestID != request.ID || claimed.CSRFingerprint != request.Fingerprint || claimed.PublicKey != r.GUIPublicKey {
		t.Fatal("renewal claim lost original CSR/key binding", err)
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE gui_certificate_jobs SET state='failed',failure_code='policy',lease_token=NULL,lease_expires_at=NULL WHERE id=$1`, nextJob); err != nil {
		t.Fatal(err)
	}
	if n, err := adapter.EnqueueRenewals(f.ctx); err != nil || n != 0 {
		t.Fatal("terminal failure created more CA work", n, err)
	}
	var audits int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.certificate_renewal_queued'`, a.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("renewal audit mismatch", err)
	}
	// Seed a second due generation so no failed/newer job masks revocation.
	// This is scheduling-only public fixture data, not a completed CA order.
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE gui_certificate_jobs SET state='issued' WHERE id=$1`, nextJob); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.ExecContext(f.ctx, `INSERT INTO gui_certificate_generations(tenant_id,device_id,request_id,job_id,generation,chain_pem,leaf_fingerprint,not_before,not_after,valid_until,renew_after,completed_lease,completed_version,issued_at)
 SELECT tenant_id,device_id,request_id,$2,2,chain_pem,leaf_fingerprint,not_before,not_after,valid_until,renew_after,gen_random_uuid(),1,issued_at FROM gui_certificate_generations WHERE id=$1`, generation, nextJob); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := adapter.EnqueueRenewals(f.ctx); err != nil || n != 0 {
		t.Fatal("revoked renewal queued", n, err)
	}
	for _, role := range []string{"nethub_web", "nethub_authz"} {
		var granted bool
		if err := f.owner.QueryRowContext(f.ctx, `SELECT has_function_privilege($1,'public.enqueue_due_gui_certificate_renewals(text,jsonb)','EXECUTE')`, role).Scan(&granted); err != nil || granted {
			t.Fatal("application renewal grant", err)
		}
	}
	t.Log("Issuer-only due renewal admission passed policy isolation, parent-lock skipping, eight concurrent scans, original request reuse, terminal suppression and revocation; seeded material is not issuance acceptance")
}
