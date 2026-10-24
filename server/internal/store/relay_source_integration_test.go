package store

import (
	"database/sql"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relayhook"
	"github.com/jackc/pgx/v5/pgconn"
)

func testRelaySourceAccess(t *testing.T, f *enrollmentFixture, web *sql.DB, tenant string) {
	t.Helper()
	record, _, actor := f.fresh(t, tenant)
	assigned, err := f.repository.Register(f.ctx, record, f.issue)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := f.signer.Verify(assigned.Claim)
	if err != nil {
		t.Fatal(err)
	}
	relay := &RelayStore{DB: f.repository.DB}
	console := &ConsoleStore{AuthStore: AuthStore{DB: web, Tenant: tenant}}
	ip := netip.MustParseAddr("192.0.2.150")
	if err = relay.Authorize(f.ctx, identity); err != nil {
		t.Fatal("valid identity failed before access grant", err)
	}
	if err = relay.AuthorizeConnection(f.ctx, identity, ip); !errors.Is(err, relayhook.ErrDenied) {
		t.Fatal("missing source grant allowed a connection", err)
	}
	grant, err := console.OpenDevice(f.ctx, actor, assigned.ID, ip)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []netip.Addr{ip, netip.MustParseAddr("::ffff:192.0.2.150")} {
		if err = relay.AuthorizeConnection(f.ctx, identity, source); err != nil {
			t.Fatal("current exact source grant refused", err)
		}
	}
	if err = relay.AuthorizeConnection(f.ctx, identity, netip.MustParseAddr("192.0.2.151")); !errors.Is(err, relayhook.ErrDenied) {
		t.Fatal("another source used the grant", err)
	}
	ipv6 := netip.MustParseAddr("2001:db8::150")
	if _, err = console.OpenDevice(f.ctx, actor, assigned.ID, ipv6); err != nil {
		t.Fatal(err)
	}
	if err = relay.AuthorizeConnection(f.ctx, identity, ipv6); err != nil {
		t.Fatal("exact IPv6 source refused", err)
	}
	var expiry time.Time
	if err = f.owner.QueryRowContext(f.ctx, `SELECT expires_at FROM device_access_grants WHERE device_id=$1 AND user_id=$2 AND source_ip=$3::inet`, assigned.ID, actor, ip.String()).Scan(&expiry); err != nil || !expiry.Equal(grant.ExpiresAt) {
		t.Fatal("connection traffic renewed access", err)
	}
	if _, err = f.owner.ExecContext(f.ctx, `UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	if err = relay.AuthorizeConnection(f.ctx, identity, ip); !errors.Is(err, relayhook.ErrDenied) {
		t.Fatal("disabled grant actor retained access", err)
	}
	if _, err = f.owner.ExecContext(f.ctx, `UPDATE users SET disabled_at=NULL WHERE id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	_, _, admin := f.fresh(t, tenant)
	if _, err = f.owner.ExecContext(f.ctx, `UPDATE users SET role='admin' WHERE id=$1`, admin); err != nil {
		t.Fatal(err)
	}
	adminIP := netip.MustParseAddr("192.0.2.155")
	if _, err = console.OpenDevice(f.ctx, admin, assigned.ID, adminIP); err != nil {
		t.Fatal(err)
	}
	if err = relay.AuthorizeConnection(f.ctx, identity, adminIP); err != nil {
		t.Fatal("administrator source grant failed", err)
	}
	if _, err = f.owner.ExecContext(f.ctx, `UPDATE users SET role='member' WHERE id=$1`, admin); err != nil {
		t.Fatal(err)
	}
	if err = relay.AuthorizeConnection(f.ctx, identity, adminIP); !errors.Is(err, relayhook.ErrDenied) {
		t.Fatal("demoted non-owner retained access", err)
	}

	// The grant expires while an unchanged row lock is held. A pre-lock expiry
	// predicate alone would accept the row when that lock is released.
	if err = f.owner.QueryRowContext(f.ctx, `WITH next AS (SELECT clock_timestamp()+interval '300 milliseconds' AS expires)
 UPDATE device_access_grants g SET expires_at=next.expires,granted_at=next.expires-interval '30 minutes' FROM next
 WHERE device_id=$1 AND user_id=$2 AND source_ip=$3::inet RETURNING expires_at`, assigned.ID, actor, ip.String()).Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	lock, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	var blocker int
	if err = lock.QueryRowContext(f.ctx, `SELECT pg_backend_pid() FROM device_access_grants WHERE device_id=$1 AND user_id=$2 AND source_ip=$3::inet FOR UPDATE`, assigned.ID, actor, ip.String()).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- relay.AuthorizeConnection(f.ctx, identity, ip) }()
	waiting := false
	for deadline := time.Now().Add(250 * time.Millisecond); time.Now().Before(deadline); {
		if err = f.owner.QueryRowContext(f.ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, blocker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !waiting {
		t.Fatal("connection never waited for the actual grant row lock")
	}
	if _, err = lock.ExecContext(f.ctx, `SELECT pg_sleep_until($1::timestamptz+interval '5 milliseconds')`, expiry); err != nil {
		t.Fatal(err)
	}
	if err = lock.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-finished; !errors.Is(err, relayhook.ErrDenied) {
		t.Fatal("grant that expired during its row-lock wait was not denied", err)
	}
	var after time.Time
	if err = f.owner.QueryRowContext(f.ctx, `SELECT expires_at FROM device_access_grants WHERE device_id=$1 AND user_id=$2 AND source_ip=$3::inet`, assigned.ID, actor, ip.String()).Scan(&after); err != nil || !after.Equal(expiry) {
		t.Fatal("denied connection extended expiry", err)
	}
	if _, err = console.OpenDevice(f.ctx, actor, assigned.ID, ip); err != nil {
		t.Fatal(err)
	}
	if err = relay.AuthorizeConnection(f.ctx, identity, ip); err != nil {
		t.Fatal("explicit renewal did not restore access", err)
	}
	if _, err = f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, assigned.ID); err != nil {
		t.Fatal(err)
	}
	if err = relay.AuthorizeConnection(f.ctx, identity, ip); !errors.Is(err, relayhook.ErrDenied) {
		t.Fatal("revoked identity used an unexpired grant", err)
	}
	for _, check := range []struct {
		db    *sql.DB
		query string
	}{{web, `SELECT device_source_access($1,'192.0.2.150')`}, {f.repository.DB, `SELECT role FROM users WHERE id=$1`}} {
		store := AuthStore{DB: check.db, Tenant: tenant}
		tx, err := store.begin(f.ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(f.ctx, check.query, actor)
		tx.Rollback()
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatal("source gate expanded runtime role authority", err)
		}
	}
	t.Log("Relay source access passed exact IPv4/IPv6, absent/wrong/expired grants, active current actor roles, unchanged-row lock expiry, explicit-only renewal, revocation and runtime role isolation")
}
