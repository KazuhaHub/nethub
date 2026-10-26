package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

type auditForwardFixture struct {
	utc, local string
	hashes     string
	tenants    []string
}

func appendAuditFixture(ctx context.Context, db *sql.DB, tenant, zone string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true),set_config('TimeZone',$2,true)`, tenant, zone); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `SELECT append_audit('system',NULL,'audit.fixture',NULL,'{"text":"private audit fixture","number":1.2000,"unicode":"☃"}'::jsonb)`); err != nil {
		return err
	}
	return tx.Commit()
}

// Seed the original function from migrations 1-2 before forward migration.
func prepareAuditForwardFixture(t *testing.T, ctx context.Context, owner *sql.DB) *auditForwardFixture {
	t.Helper()
	f := &auditForwardFixture{}
	t.Cleanup(func() { f.cleanup(t, owner) })
	for _, target := range []*string{&f.utc, &f.local} {
		if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('Audit migration fixture') RETURNING id`).Scan(target); err != nil {
			t.Fatal(err)
		}
		f.tenants = append(f.tenants, *target)
	}
	for _, entry := range []struct{ tenant, zone string }{{f.utc, "UTC"}, {f.utc, "UTC"}, {f.local, "America/Los_Angeles"}} {
		if err := appendAuditFixture(ctx, owner, entry.tenant, entry.zone); err != nil {
			t.Fatal(err)
		}
	}
	if err := owner.QueryRowContext(ctx, `SELECT string_agg(id::text||':'||encode(entry_hash,'hex'),',' ORDER BY id) FROM audit_log WHERE tenant_id IN ($1,$2)`, f.utc, f.local).Scan(&f.hashes); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *auditForwardFixture) cleanup(t *testing.T, owner *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, tenant := range f.tenants {
		if _, err := owner.ExecContext(ctx, `DELETE FROM audit_log WHERE tenant_id=$1`, tenant); err != nil {
			t.Error("audit fixture cleanup failed")
			continue
		}
		if _, err := owner.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenant); err != nil {
			t.Error("audit tenant cleanup failed")
		}
	}
	f.tenants = nil
}

func testAuditForwardAndDoctor(t *testing.T, ctx context.Context, owner, web, authz *sql.DB, f *auditForwardFixture, defaultTenant string) {
	t.Helper()
	var hashes string
	var legacy int
	if err := owner.QueryRowContext(ctx, `SELECT string_agg(id::text||':'||encode(entry_hash,'hex'),',' ORDER BY id),count(*) FILTER(WHERE hash_version=1) FROM audit_log WHERE tenant_id IN ($1,$2)`, f.utc, f.local).Scan(&hashes, &legacy); err != nil || hashes != f.hashes || legacy != 3 {
		t.Fatal("forward migration changed legacy hashes or their encoding version", err)
	}
	for _, entry := range []struct {
		tenant, zone string
		count        int64
	}{{f.utc, "UTC", 2}, {f.local, "America/Los_Angeles", 1}} {
		result, err := VerifyAuditChain(ctx, web, entry.tenant, entry.zone)
		if err != nil || result.Entries != entry.count || result.LegacyEntries != entry.count {
			t.Fatal("legacy chain failed with its original writer timezone", err)
		}
	}
	if result, err := VerifyAuditChain(ctx, web, f.local, "UTC"); !errors.Is(err, ErrAuditChainInvalid) || result != (AuditChainResult{}) {
		t.Fatal("wrong legacy timezone was silently accepted")
	}
	if _, err := VerifyAuditChain(ctx, authz, f.utc, "UTC"); !errors.Is(err, ErrAuditChainUnavailable) {
		t.Fatal("authz unexpectedly read audit history")
	}
	if _, err := VerifyAuditChain(ctx, web, "00000000-0000-0000-0000-000000000000", "UTC"); !errors.Is(err, ErrAuditChainUnavailable) {
		t.Fatal("missing tenant reported as a valid empty chain")
	}

	blocker, err := owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(ctx, `SELECT id FROM tenants WHERE id=$1 FOR UPDATE`, f.utc); err != nil {
		t.Fatal(err)
	}
	var writers sync.WaitGroup
	defer func() { blocker.Rollback(); writers.Wait() }()
	errorsOut := make(chan error, 8)
	for index := range 8 {
		writers.Go(func() {
			db, zone := web, "Asia/Tokyo"
			if index%2 == 1 {
				db, zone = authz, "America/Los_Angeles"
			}
			for range 2 {
				if err := appendAuditFixture(ctx, db, f.utc, zone); err != nil {
					errorsOut <- err
					return
				}
			}
		})
	}
	reader, stop := context.WithTimeout(ctx, 3*time.Second)
	prefix, readErr := VerifyAuditChain(reader, web, f.utc, "UTC")
	stop()
	if readErr != nil || prefix.Entries != 2 {
		blocker.Rollback()
		writers.Wait()
		t.Fatal("read-only verification waited for append locks or saw uncommitted entries", readErr)
	}
	if err = blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	writers.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	result, err := VerifyAuditChain(ctx, web, f.utc, "UTC")
	if err != nil || result.Entries != 18 || result.LegacyEntries != 2 {
		t.Fatal("concurrent Web/authz append or timezone-independent encoding failed", result, err)
	}
	var current int
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND hash_version=2`, f.utc).Scan(&current); err != nil || current != 16 {
		t.Fatal("new appends did not use version 2")
	}
	// A corrupted other tenant must not affect the selected snapshot.
	if _, err = owner.ExecContext(ctx, `UPDATE audit_log SET payload='{"other":"changed"}' WHERE tenant_id=$1`, f.local); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyAuditChain(ctx, web, f.utc, "UTC"); err != nil {
		t.Fatal("other tenant polluted audit verification", err)
	}

	for _, test := range []struct{ name, query string }{
		{"payload", `UPDATE audit_log SET payload='{"private":"changed"}' WHERE tenant_id=$1 AND sequence=2`},
		{"link", `UPDATE audit_log SET prev_hash=decode(repeat('00',32),'hex') WHERE tenant_id=$1 AND sequence=2`},
		{"gap", `UPDATE audit_log SET sequence=1000 WHERE tenant_id=$1 AND sequence=2`},
		{"short_hash", `UPDATE audit_log SET entry_hash=decode('00','hex') WHERE tenant_id=$1 AND sequence=2`},
		{"encoding_downgrade", `UPDATE audit_log SET hash_version=1 WHERE tenant_id=$1 AND sequence=2`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var tenant string
			if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('Audit integrity fixture') RETURNING id`).Scan(&tenant); err != nil {
				t.Fatal(err)
			}
			f.tenants = append(f.tenants, tenant)
			for range 2 {
				if err := appendAuditFixture(ctx, web, tenant, "UTC"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := owner.ExecContext(ctx, test.query, tenant); err != nil {
				t.Fatal(err)
			}
			result, err := VerifyAuditChain(ctx, web, tenant, "UTC")
			if !errors.Is(err, ErrAuditChainInvalid) || result != (AuditChainResult{}) {
				t.Fatal("corrupted history returned a successful or partial result", test.name)
			}
		})
	}
	t.Run("valid_oversized_record", func(t *testing.T) {
		var tenant string
		if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('Oversized audit fixture') RETURNING id`).Scan(&tenant); err != nil {
			t.Fatal(err)
		}
		f.tenants = append(f.tenants, tenant)
		tx, err := owner.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.ExecContext(ctx, `SELECT append_audit('system',NULL,'audit.oversize',NULL,jsonb_build_object('text',repeat('x',1048576)))`); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if result, err := VerifyAuditChain(ctx, web, tenant, "UTC"); !errors.Is(err, ErrAuditChainInvalid) || result != (AuditChainResult{}) {
			t.Fatal("valid oversized record bypassed the verification budget")
		}
	})
	if t.Failed() {
		return
	}
	f.cleanup(t, owner)

	binary := os.Getenv("NETHUB_AUTHZ_TEST_BINARY")
	if binary == "" {
		t.Fatal("compiled CLI fixture is required")
	}
	if err = appendAuditFixture(ctx, web, defaultTenant, "America/Los_Angeles"); err != nil {
		t.Fatal(err)
	}
	var id, before string
	if err = owner.QueryRowContext(ctx, `SELECT id,encode(entry_hash,'hex') FROM audit_log WHERE tenant_id=$1 AND action='audit.fixture'`, defaultTenant).Scan(&id, &before); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := owner.ExecContext(ctx, `DELETE FROM audit_log WHERE id=$1`, id); err != nil {
			t.Error("compiled doctor fixture cleanup failed")
		}
	}()
	runDoctor := func(want int) {
		t.Helper()
		command := exec.CommandContext(ctx, binary, "doctor", "--audit", "--host", "127.0.0.1", "--database", "nethub", "--password-file", "/run/secrets/pg_nethub_web", "--sslmode", "disable")
		output, err := command.CombinedOutput()
		status := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("compiled doctor did not execute")
			}
			status = exit.ExitCode()
		}
		if status != want || strings.Contains(string(output), "private audit fixture") {
			t.Fatal("compiled doctor status or diagnostic privacy failed", status)
		}
		if want == 0 && !strings.Contains(string(output), "Audit chain verified: entries=1, legacy=0, read-only snapshot") {
			t.Fatal("compiled doctor did not verify the complete fixture")
		}
		if want != 0 && strings.Contains(string(output), "Audit chain verified:") {
			t.Fatal("compiled doctor printed success after failure")
		}
	}
	runDoctor(0)
	if _, err = owner.ExecContext(ctx, `UPDATE audit_log SET payload='{"text":"private audit fixture changed"}' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	runDoctor(1)
	var after, payload string
	if err = owner.QueryRowContext(ctx, `SELECT encode(entry_hash,'hex'),payload->>'text' FROM audit_log WHERE id=$1`, id).Scan(&after, &payload); err != nil || after != before || payload != "private audit fixture changed" {
		t.Fatal("doctor rewrote history", err)
	}
	t.Log("Audit SQL verified retained legacy hashes, explicit legacy timezone, timezone-independent version 2, concurrent Web/authz writers, tenant/role fences, corruption refusal and actual compiled read-only doctor without payload disclosure or repair")
}
