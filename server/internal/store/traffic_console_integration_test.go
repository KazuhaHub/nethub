package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/relaystate"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"github.com/jackc/pgx/v5/pgconn"
)

func testTrafficConsole(t *testing.T, ctx context.Context, owner, authz, db, backup *sql.DB) {
	t.Helper()
	var tenants []string
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, tenant := range tenants {
			for _, query := range []string{`DELETE FROM audit_log WHERE tenant_id=$1`, `DELETE FROM tenant_traffic_settings WHERE tenant_id=$1`, `DELETE FROM relay_traffic_months WHERE tenant_id=$1`, `DELETE FROM devices WHERE tenant_id=$1`, `DELETE FROM users WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
				if _, err := owner.ExecContext(clean, query, tenant); err != nil {
					t.Error("traffic console fixture cleanup failed")
				}
			}
		}
	})
	newTenant := func() string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('Traffic console fixture') RETURNING id`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, id)
		return id
	}
	user := func(tenant, email, role string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role) VALUES($1,$2,$3) RETURNING id`, tenant, email, role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	device := func(tenant, actor, subdomain string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO devices(tenant_id,owner_user_id,platform,device_secret_hash,subdomain,agent_protocol_version) VALUES($1,$2,'opnsense','traffic-console-fixture',$3,'fixture') RETURNING id`, tenant, actor, subdomain).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b := newTenant(), newTenant()
	admin, member := user(a, "traffic-admin@example.com", "admin"), user(a, "traffic-member@example.com", "member")
	foreign := user(b, "traffic-foreign@example.com", "admin")
	first, second, other := device(a, admin, "tcap0001"), device(a, member, "tcap0002"), device(b, foreign, "tcap0003")
	at := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	samples := []relaystate.TrafficSample{{DeviceID: first, Subdomain: "tcap0001", InBytes: 10, OutBytes: 20}, {DeviceID: second, Subdomain: "tcap0002", InBytes: 30, OutBytes: 40}, {DeviceID: other, Subdomain: "tcap0003", InBytes: 1000, OutBytes: 2000}}
	if err := (&ObservationStore{DB: authz}).ObserveTraffic(ctx, at, samples); err != nil {
		t.Fatal(err)
	}
	store := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: a}}
	query := web.TrafficQuery{Month: at.Format("2006-01"), Limit: 1}
	page, err := store.Traffic(ctx, admin, query)
	if err != nil || page.TotalBytes != "100" || page.InBytes != "40" || page.OutBytes != "60" || len(page.Items) != 1 || page.NextCursor == nil || page.WarningBytes != nil || page.WarningRevision != 0 || page.LastObservedAt == nil {
		t.Fatal("administrator traffic report lost its tenant totals or page", err)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(*page.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	query.AfterID = string(decoded)
	next, err := store.Traffic(ctx, admin, query)
	if err != nil || next.TotalBytes != "100" || len(next.Items) != 1 || next.NextCursor != nil || next.Items[0].DeviceID == page.Items[0].DeviceID {
		t.Fatal("traffic pagination changed the monthly total or repeated a row", err)
	}
	for _, item := range []web.TrafficDevice{page.Items[0], next.Items[0]} {
		if item.DeviceID != first && item.DeviceID != second {
			t.Fatal("foreign traffic entered an administrator page")
		}
	}
	if _, err := store.Traffic(ctx, member, query); !errors.Is(err, web.ErrForbidden) {
		t.Fatal("member read tenant traffic")
	}
	if _, err := store.Traffic(ctx, foreign, query); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("foreign actor read tenant traffic")
	}
	oldMonth := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC).Add(-time.Hour).Format("2006-01")
	empty, err := store.Traffic(ctx, admin, web.TrafficQuery{Month: oldMonth, Limit: 50})
	if err != nil || empty.TotalBytes != "0" || len(empty.Items) != 0 || empty.Items == nil || empty.LastObservedAt != nil {
		t.Fatal("unobserved month was not an explicit empty report", err)
	}

	ip := netip.MustParseAddr("192.0.2.181")
	if _, err := store.SetTrafficWarning(ctx, member, "50", 0, ip); !errors.Is(err, web.ErrForbidden) {
		t.Fatal("member changed the tenant warning")
	}
	setting, err := store.SetTrafficWarning(ctx, admin, "50", 0, ip)
	if err != nil || setting.Revision != 1 || setting.WarningBytes == nil || *setting.WarningBytes != "50" {
		t.Fatal("administrator warning update failed", err)
	}
	unchanged, err := store.SetTrafficWarning(ctx, admin, "50", 1, ip)
	if err != nil || unchanged.Revision != 1 {
		t.Fatal("unchanged warning created another revision", err)
	}
	if _, err := store.SetTrafficWarning(ctx, admin, "100", 0, ip); !errors.Is(err, web.ErrTrafficChanged) {
		t.Fatal("stale warning update overwrote current policy")
	}
	if _, err := (&ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: b}}).SetTrafficWarning(ctx, foreign, "999", 0, ip); err != nil {
		t.Fatal(err)
	}
	query.AfterID = ""
	page, err = store.Traffic(ctx, admin, query)
	if err != nil || page.WarningBytes == nil || *page.WarningBytes != "50" || page.WarningRevision != 1 {
		t.Fatal("tenant warning was absent or substituted", err)
	}

	if _, err := owner.ExecContext(ctx, `REVOKE EXECUTE ON FUNCTION append_audit(text,uuid,text,uuid,jsonb) FROM nethub_web`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := owner.ExecContext(clean, `GRANT EXECUTE ON FUNCTION append_audit(text,uuid,text,uuid,jsonb) TO nethub_web`); err != nil {
			t.Error("traffic audit permission restoration failed")
		}
	})
	if _, err := store.SetTrafficWarning(ctx, admin, "75", 1, ip); err == nil {
		t.Fatal("warning committed without its audit")
	}
	if _, err := owner.ExecContext(ctx, `GRANT EXECUTE ON FUNCTION append_audit(text,uuid,text,uuid,jsonb) TO nethub_web`); err != nil {
		t.Fatal(err)
	}
	page, err = store.Traffic(ctx, admin, query)
	if err != nil || page.WarningRevision != 1 || page.WarningBytes == nil || *page.WarningBytes != "50" {
		t.Fatal("failed audit changed warning state", err)
	}
	setting, err = store.SetTrafficWarning(ctx, admin, "0", 1, ip)
	if err != nil || setting.WarningBytes != nil || setting.Revision != 2 {
		t.Fatal("warning disable failed", err)
	}
	var successes atomic.Int32
	var workers sync.WaitGroup
	failures := make(chan error, 8)
	for index := range 8 {
		workers.Go(func() {
			value := []string{"101", "102", "103", "104", "105", "106", "107", "108"}[index]
			_, err := store.SetTrafficWarning(ctx, admin, value, 2, ip)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, web.ErrTrafficChanged) {
				failures <- err
			}
		})
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Fatal("concurrent warning mutation failed outside revision conflicts", err)
	}
	if successes.Load() != 1 {
		t.Fatal("concurrent warning edits did not admit exactly one change")
	}
	var audits int
	if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='traffic.warning_updated'`, a).Scan(&audits); err != nil || audits != 3 {
		t.Fatal("warning audit was duplicated or lost", err)
	}
	var forced bool
	if err := owner.QueryRowContext(ctx, `SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='tenant_traffic_settings'::regclass`).Scan(&forced); err != nil || !forced {
		t.Fatal("warning settings lost forced RLS", err)
	}
	_, err = authz.ExecContext(ctx, `SELECT * FROM tenant_traffic_settings`)
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatal("authz gained access to warning policy")
	}
	var archived int
	if err := backup.QueryRowContext(ctx, `SELECT count(*) FROM tenant_traffic_settings WHERE tenant_id IN ($1,$2)`, a, b).Scan(&archived); err != nil || archived != 2 {
		t.Fatal("backup omitted tenant warning settings", err)
	}
	if _, err := owner.ExecContext(ctx, `UPDATE users SET role='member' WHERE id=$1`, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetTrafficWarning(ctx, admin, "200", 3, ip); !errors.Is(err, web.ErrForbidden) {
		t.Fatal("demoted administrator changed warning policy")
	}
	var revoked bool
	if err := owner.QueryRowContext(ctx, `SELECT revoked FROM devices WHERE id=$1`, first).Scan(&revoked); err != nil || revoked {
		t.Fatal("warning policy changed device authority", err)
	}
	t.Log("Traffic console SQL verified tenant-wide totals across pages, explicit empty months, live administrator checks, private warning policy, atomic audit rollback, no-op preservation and eight-way revision conflicts without enforcement")
}
