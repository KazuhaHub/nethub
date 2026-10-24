package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func testExplicitDeviceAccess(t *testing.T, ctx context.Context, owner, db, authz *sql.DB, tenant, otherTenant string) {
	t.Helper()
	actor := func(role, email string) string {
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role) VALUES($1,$2,$3) RETURNING id`, tenant, email, role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	member := actor("member", "open-member@example.com")
	other := actor("member", "open-other@example.com")
	admin := actor("admin", "open-admin@example.com")
	device := func(deviceTenant, user, label string) string {
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO devices(tenant_id,owner_user_id,hostname,platform,device_secret_hash,subdomain,agent_protocol_version) VALUES($1,$2,'Open fixture','opnsense','isolated fixture hash',$3,'1.5.0') RETURNING id`, deviceTenant, user, label).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	memberDevice := device(tenant, member, "open-own")
	otherDevice := device(tenant, other, "open-other")
	var foreignActor string
	if err := owner.QueryRowContext(ctx, `SELECT id FROM users WHERE tenant_id=$1 LIMIT 1`, otherTenant).Scan(&foreignActor); err != nil {
		t.Fatal(err)
	}
	foreignDevice := device(otherTenant, foreignActor, "open-foreign")
	repository := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}}
	ip := netip.MustParseAddr("::ffff:192.0.2.150")
	for _, target := range []string{otherDevice, foreignDevice, "00000000-0000-0000-0000-000000000000"} {
		if _, err := repository.OpenDevice(ctx, member, target, ip); !errors.Is(err, web.ErrDeviceUnavailable) {
			t.Fatal("foreign or missing device granted access", err)
		}
	}
	var deniedRows int
	if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM device_access_grants WHERE user_id=$1`, member).Scan(&deniedRows); err != nil || deniedRows != 0 {
		t.Fatal("denied request persisted a grant", err)
	}
	first, err := repository.OpenDevice(ctx, member, memberDevice, ip)
	if err != nil || first.Subdomain != "open-own" {
		t.Fatal("owned device grant failed", err)
	}
	var storedIP string
	var storedExpiry time.Time
	var lifetime float64
	if err = owner.QueryRowContext(ctx, `SELECT host(source_ip),expires_at,extract(epoch FROM expires_at-granted_at) FROM device_access_grants WHERE device_id=$1 AND user_id=$2`, memberDevice, member).Scan(&storedIP, &storedExpiry, &lifetime); err != nil || storedIP != "192.0.2.150" || lifetime != 1800 || !storedExpiry.Equal(first.ExpiresAt) {
		t.Fatal("grant lost exact normalized IP or database lifetime", err)
	}
	if _, err = owner.ExecContext(ctx, `UPDATE device_access_grants SET granted_at=granted_at-interval '31 minutes',expires_at=expires_at-interval '31 minutes' WHERE device_id=$1 AND user_id=$2`, memberDevice, member); err != nil {
		t.Fatal(err)
	}
	var expired time.Time
	if err = owner.QueryRowContext(ctx, `SELECT expires_at FROM device_access_grants WHERE device_id=$1 AND user_id=$2`, memberDevice, member).Scan(&expired); err != nil {
		t.Fatal(err)
	}
	if _, err = repository.Devices(ctx, member, web.DeviceQuery{Limit: 50}); err != nil {
		t.Fatal(err)
	}
	read := AuthStore{DB: authz, Tenant: tenant}
	tx, err := read.begin(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	var live int
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM device_access_grants WHERE device_id=$1 AND expires_at>clock_timestamp()`, memberDevice).Scan(&live)
	tx.Rollback()
	if err != nil || live != 0 {
		t.Fatal("expired grant remained active", err)
	}
	var afterRead time.Time
	if err = owner.QueryRowContext(ctx, `SELECT expires_at FROM device_access_grants WHERE device_id=$1 AND user_id=$2`, memberDevice, member).Scan(&afterRead); err != nil || !afterRead.Equal(expired) {
		t.Fatal("read-only observation extended access", err)
	}
	renewed, err := repository.OpenDevice(ctx, member, memberDevice, ip)
	if err != nil || !renewed.ExpiresAt.After(expired) {
		t.Fatal("explicit repeat did not renew access", err)
	}
	ipv6 := netip.MustParseAddr("2001:db8::150")
	if _, err = repository.OpenDevice(ctx, member, memberDevice, ipv6); err != nil {
		t.Fatal("exact IPv6 grant failed", err)
	}
	if _, err = repository.OpenDevice(ctx, admin, otherDevice, ip); err != nil {
		t.Fatal("administrator could not open tenant device", err)
	}
	var count int
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM device_access_grants WHERE device_id=$1 AND user_id=$2`, memberDevice, member).Scan(&count); err != nil || count != 2 {
		t.Fatal("repeat duplicated a grant or IP families were conflated", err)
	}
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE actor_id=$1 AND action='device.access_granted' AND target_device_id=$2 AND payload->>'source_ip' IN ('192.0.2.150','2001:db8::150')`, member, memberDevice).Scan(&count); err != nil || count != 3 {
		t.Fatal("successful opens lost actor/device/source audit binding", err)
	}
	assignment, err := owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer assignment.Rollback()
	var blocker int
	if err = assignment.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	if _, err = assignment.ExecContext(ctx, `UPDATE devices SET subdomain='open-new' WHERE id=$1`, memberDevice); err != nil {
		t.Fatal(err)
	}
	type openResult struct {
		access web.DeviceAccess
		err    error
	}
	finished := make(chan openResult, 1)
	boundedAssignment, cancelAssignment := context.WithTimeout(ctx, 6*time.Second)
	defer cancelAssignment()
	go func() {
		access, err := repository.OpenDevice(boundedAssignment, member, memberDevice, ip)
		finished <- openResult{access, err}
	}()
	waitForBlock := func(pid int) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); ; {
			var waiting bool
			if err := owner.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("open never waited for the actual row lock")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitForBlock(blocker)
	if err = assignment.Commit(); err != nil {
		t.Fatal(err)
	}
	completed := <-finished
	if completed.err != nil || completed.access.Subdomain != "open-new" {
		t.Fatal("open returned a destination from before the assignment lock", completed.err)
	}
	if _, err = owner.ExecContext(ctx, `UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1`, other); err != nil {
		t.Fatal(err)
	}
	if _, err = repository.OpenDevice(ctx, other, otherDevice, ip); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("disabled actor opened a device", err)
	}
	if _, err = owner.ExecContext(ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp(),revoked_by_user_id=$1 WHERE id=$2`, admin, otherDevice); err != nil {
		t.Fatal(err)
	}
	if _, err = repository.OpenDevice(ctx, admin, otherDevice, ip); !errors.Is(err, web.ErrDeviceRevoked) {
		t.Fatal("revoked device granted access", err)
	}
	if _, err = repository.OpenDevice(ctx, member, otherDevice, ip); !errors.Is(err, web.ErrDeviceUnavailable) {
		t.Fatal("revocation status leaked to a non-owner", err)
	}
	if _, err = repository.OpenDevice(ctx, member, memberDevice, netip.MustParseAddr("fe80::1%test")); err == nil {
		t.Fatal("scoped source address accepted")
	}

	// A blocked audit must not leave a separately committed access grant.
	lock, err := owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if err = lock.QueryRowContext(ctx, `SELECT pg_backend_pid() FROM tenants WHERE id=$1 FOR UPDATE`, tenant).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	auditFinished := make(chan error, 1)
	go func() {
		_, err := repository.OpenDevice(bounded, member, memberDevice, netip.MustParseAddr("192.0.2.151"))
		auditFinished <- err
	}()
	waitForBlock(blocker)
	cancel()
	err = <-auditFinished
	lock.Rollback()
	if err == nil {
		t.Fatal("blocked audit returned a committed grant")
	}
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM device_access_grants WHERE device_id=$1 AND source_ip='192.0.2.151'`, memberDevice).Scan(&count); err != nil || count != 0 {
		t.Fatal("cancelled audit left a partial grant", err)
	}
	t.Log("Explicit device access passed owner/admin/tenant and revocation boundaries, exact IPv4/IPv6, fixed database expiry, read-only non-renewal, audited explicit renewal, assignment lock refresh and atomic cancellation")
}
