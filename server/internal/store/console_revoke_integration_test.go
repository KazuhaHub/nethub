package store

import (
	"database/sql"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func testConsoleRevocation(t *testing.T, f *enrollmentFixture, webRole *sql.DB, tenant, foreignTenant string) {
	t.Helper()
	makeDevice := func(scope string) (string, string) {
		r, _, actor := f.fresh(t, scope)
		assignment, err := f.repository.Register(f.ctx, r, f.issue)
		if err != nil {
			t.Fatal(err)
		}
		return assignment.ID, actor
	}
	device, actor := makeDevice(tenant)
	other, otherActor := makeDevice(tenant)
	foreign, _ := makeDevice(foreignTenant)
	repository := &ConsoleStore{AuthStore: AuthStore{DB: webRole, Tenant: tenant}}
	ip := netip.MustParseAddr("::ffff:192.0.2.166")
	for _, id := range []string{other, foreign, "00000000-0000-0000-0000-000000000000"} {
		if _, err := repository.RevokeDevice(f.ctx, actor, id, ip); !errors.Is(err, web.ErrDeviceUnavailable) {
			t.Fatal("foreign or missing revocation accepted", err)
		}
	}
	var wg sync.WaitGroup
	results := make(chan web.DeviceRevocation, 8)
	failures := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			result, err := repository.RevokeDevice(f.ctx, actor, device, ip)
			results <- result
			failures <- err
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("concurrent revocation failed", err)
		}
	}
	var stamp time.Time
	for result := range results {
		if !result.Revoked || result.RevokedAt.IsZero() {
			t.Fatal("revocation receipt missing")
		}
		if stamp.IsZero() {
			stamp = result.RevokedAt
		}
		if !stamp.Equal(result.RevokedAt) {
			t.Fatal("retry changed revocation timestamp")
		}
	}
	var count int
	var source, storedActor string
	if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*),min(payload->>'source_ip'),min(actor_id::text) FROM audit_log WHERE target_device_id=$1 AND action='device.revoked'`, device).Scan(&count, &source, &storedActor); err != nil || count != 1 || source != "192.0.2.166" || storedActor != actor {
		t.Fatal("revocation audit missing or duplicated", err)
	}
	if _, err := repository.OpenDevice(f.ctx, actor, device, ip); !errors.Is(err, web.ErrDeviceRevoked) {
		t.Fatal("revoked device still opened", err)
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE users SET role='admin' WHERE id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.RevokeDevice(f.ctx, actor, other, ip); err != nil {
		t.Fatal("tenant admin could not revoke another owner's device", err)
	}
	// Demotion committed while the actor lock is held must win over stale scope.
	target, _ := makeDevice(tenant)
	blocker, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(f.ctx, `UPDATE users SET role='member' WHERE id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := repository.RevokeDevice(f.ctx, actor, target, ip); done <- err }()
	select {
	case err := <-done:
		t.Fatal("revocation bypassed actor lock", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err = blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, web.ErrDeviceUnavailable) {
		t.Fatal("demoted admin retained stale authority", err)
	}
	if _, err = f.owner.ExecContext(f.ctx, `UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1`, otherActor); err != nil {
		t.Fatal(err)
	}
	if _, err = repository.RevokeDevice(f.ctx, otherActor, other, ip); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("disabled actor could retry revocation", err)
	}
	// Force audit failure only for this action and prove the device write rolls back.
	fault, owner := makeDevice(tenant)
	if _, err = f.owner.ExecContext(f.ctx, `CREATE FUNCTION reject_console_revocation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='device.revoked' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$;
CREATE TRIGGER reject_console_revocation_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_console_revocation_audit()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := f.owner.ExecContext(f.ctx, `DROP TRIGGER IF EXISTS reject_console_revocation_audit ON audit_log; DROP FUNCTION IF EXISTS reject_console_revocation_audit()`); err != nil {
			t.Error(err)
		}
	}()
	if _, err = repository.RevokeDevice(f.ctx, owner, fault, ip); err == nil {
		t.Fatal("audit failure returned success")
	}
	var revoked bool
	if err = f.owner.QueryRowContext(f.ctx, `SELECT revoked FROM devices WHERE id=$1`, fault).Scan(&revoked); err != nil || revoked {
		t.Fatal("audit failure left a committed revocation", err)
	}
	t.Log("Console revocation passed owner/admin/tenant isolation, eight exact concurrent retries, immutable first timestamp, one normalized-source audit, revoked Open denial, actor-lock demotion, disabled actor and audit-failure rollback")
}
