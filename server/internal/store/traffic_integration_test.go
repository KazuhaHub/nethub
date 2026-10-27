package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaystate"
	"github.com/jackc/pgx/v5/pgconn"
)

func testRelayTraffic(t *testing.T, ctx context.Context, owner, authz, web, backup *sql.DB, tenantA, tenantB string) {
	t.Helper()
	type fixture struct{ tenant, device, user, subdomain string }
	var owned []fixture
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, f := range owned {
			for _, query := range []string{`DELETE FROM relay_traffic_months WHERE device_id=$1`, `DELETE FROM devices WHERE id=$1`} {
				if f.device == "" {
					continue
				}
				if _, err := owner.ExecContext(clean, query, f.device); err != nil {
					t.Error("traffic fixture cleanup failed")
				}
			}
			if _, err := owner.ExecContext(clean, `DELETE FROM users WHERE id=$1`, f.user); err != nil {
				t.Error("traffic actor cleanup failed")
			}
		}
	})
	makeDevice := func(t *testing.T, tenant string) fixture {
		t.Helper()
		f := fixture{tenant: tenant, subdomain: fmt.Sprintf("tc%06d", len(owned)+1)}
		if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role) VALUES($1,$2,'member') RETURNING id`, tenant, f.subdomain+"@traffic.example").Scan(&f.user); err != nil {
			t.Fatal(err)
		}
		owned = append(owned, f)
		if err := owner.QueryRowContext(ctx, `INSERT INTO devices(tenant_id,owner_user_id,platform,device_secret_hash,subdomain,agent_protocol_version) VALUES($1,$2,'opnsense','traffic-fixture-only',$3,'fixture') RETURNING id`, tenant, f.user, f.subdomain).Scan(&f.device); err != nil {
			t.Fatal(err)
		}
		owned[len(owned)-1] = f
		return f
	}
	storage := &ObservationStore{DB: authz}
	sample := func(f fixture, incoming, outgoing int64) relaystate.TrafficSample {
		return relaystate.TrafficSample{DeviceID: f.device, Subdomain: f.subdomain, InBytes: incoming, OutBytes: outgoing}
	}
	current := func() time.Time { return time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond) }
	record := func(t *testing.T, at time.Time, values ...relaystate.TrafficSample) {
		t.Helper()
		if err := storage.ObserveTraffic(ctx, at, values); err != nil {
			t.Fatal("bounded traffic observation failed", err)
		}
	}
	check := func(t *testing.T, f fixture, month, incoming, outgoing string, resets int64) {
		t.Helper()
		var in, out string
		var count int64
		if err := owner.QueryRowContext(ctx, `SELECT in_bytes::text,out_bytes::text,reset_events FROM relay_traffic_months WHERE tenant_id=$1 AND device_id=$2 AND month_start=$3::date`, f.tenant, f.device, month+"-01").Scan(&in, &out, &count); err != nil || in != incoming || out != outgoing || count != resets {
			t.Fatal("monthly traffic fact mismatch", err)
		}
	}
	empty := func(t *testing.T, f fixture) {
		t.Helper()
		var count int
		if err := owner.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM relay_traffic_samples WHERE device_id=$1)+(SELECT count(*) FROM relay_traffic_months WHERE device_id=$1)`, f.device).Scan(&count); err != nil || count != 0 {
			t.Fatal("unverified sample created traffic facts", err)
		}
	}
	withTenant := func(t *testing.T, db *sql.DB, tenant string, action func(*sql.Tx)) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		action(tx)
	}
	t.Run("durable_deltas_replay_and_resets", func(t *testing.T) {
		f := makeDevice(t, tenantA)
		at := current()
		var before, after string
		if err := owner.QueryRowContext(ctx, `SELECT to_jsonb(d)::text FROM devices d WHERE id=$1`, f.device).Scan(&before); err != nil {
			t.Fatal(err)
		}
		record(t, at, sample(f, 100, 200))
		record(t, at, sample(f, 100, 200))
		record(t, at.Add(time.Millisecond), sample(f, 130, 250))
		// A fresh pool cannot depend on process or connection-local baselines.
		fresh, err := OpenRole(ctx, DatabaseConfig{Host: "127.0.0.1", Port: 5432, Database: "nethub", PasswordFile: "/run/secrets/pg_nethub_authz", SSLMode: "disable"}, "nethub_authz")
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Close()
		if err := (&ObservationStore{DB: fresh}).ObserveTraffic(ctx, at.Add(2*time.Millisecond), []relaystate.TrafficSample{sample(f, 130, 250)}); err != nil {
			t.Fatal(err)
		}
		record(t, at.Add(-time.Millisecond), sample(f, 999, 999))
		record(t, at.Add(3*time.Millisecond), sample(f, 5, 280))
		check(t, f, at.Format("2006-01"), "135", "280", 1)
		if err := owner.QueryRowContext(ctx, `SELECT to_jsonb(d)::text FROM devices d WHERE id=$1`, f.device).Scan(&after); err != nil || after != before {
			t.Fatal("telemetry changed device authority or liveness", err)
		}
		var grants int
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM device_access_grants WHERE device_id=$1`, f.device).Scan(&grants); err != nil || grants != 0 {
			t.Fatal("telemetry created an access grant", err)
		}
	})
	t.Run("offline_requires_prior_assignment", func(t *testing.T) {
		f := makeDevice(t, tenantA)
		at := current()
		offline := sample(f, 20, 30)
		offline.Subdomain = ""
		record(t, at, offline)
		empty(t, f)
		wrong := sample(f, 100, 200)
		wrong.Subdomain = "wrong001"
		record(t, at.Add(time.Millisecond), wrong)
		empty(t, f)
		record(t, at.Add(2*time.Millisecond), sample(f, 10, 20))
		record(t, at.Add(3*time.Millisecond), offline)
		check(t, f, at.Format("2006-01"), "20", "30", 0)
	})
	t.Run("concurrent_duplicate_is_not_additive", func(t *testing.T) {
		f := makeDevice(t, tenantA)
		at := current()
		var workers sync.WaitGroup
		failures := make(chan error, 8)
		for range 8 {
			workers.Go(func() { failures <- storage.ObserveTraffic(ctx, at, []relaystate.TrafficSample{sample(f, 50, 70)}) })
		}
		workers.Wait()
		close(failures)
		for err := range failures {
			if err != nil {
				t.Fatal("concurrent traffic storage failed", err)
			}
		}
		check(t, f, at.Format("2006-01"), "50", "70", 0)
	})
	t.Run("month_rollover_retains_prior_facts", func(t *testing.T) {
		f := makeDevice(t, tenantA)
		at := current()
		old := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC).Add(-time.Hour)
		if _, err := owner.ExecContext(ctx, `INSERT INTO relay_traffic_samples VALUES($1,$2,($3::timestamptz AT TIME ZONE 'UTC')::date,100,200,$3)`, f.tenant, f.device, old); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.ExecContext(ctx, `INSERT INTO relay_traffic_months(tenant_id,device_id,month_start,in_bytes,out_bytes,first_observed_at,last_observed_at) VALUES($1,$2,$3::date,100,200,$4,$4)`, f.tenant, f.device, old.Format("2006-01")+"-01", old); err != nil {
			t.Fatal(err)
		}
		record(t, at, sample(f, 10, 20))
		check(t, f, old.Format("2006-01"), "100", "200", 0)
		check(t, f, at.Format("2006-01"), "10", "20", 0)
	})
	t.Run("wide_counters_and_removed_device_history", func(t *testing.T) {
		f := makeDevice(t, tenantA)
		at := current()
		record(t, at, sample(f, math.MaxInt64, math.MaxInt64))
		var total string
		if err := owner.QueryRowContext(ctx, `SELECT (in_bytes+out_bytes)::text FROM relay_traffic_months WHERE device_id=$1`, f.device).Scan(&total); err != nil || total != "18446744073709551614" {
			t.Fatal("traffic total lost integer precision", err)
		}
		if _, err := owner.ExecContext(ctx, `DELETE FROM devices WHERE id=$1`, f.device); err != nil {
			t.Fatal(err)
		}
		check(t, f, at.Format("2006-01"), "9223372036854775807", "9223372036854775807", 0)
	})
	t.Run("tenant_and_role_boundaries", func(t *testing.T) {
		a, b := makeDevice(t, tenantA), makeDevice(t, tenantB)
		at := current()
		record(t, at, sample(a, 11, 12), sample(b, 21, 22))
		data, _ := json.Marshal([]relaystate.TrafficSample{sample(b, 999, 999)})
		withTenant(t, authz, tenantA, func(tx *sql.Tx) {
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT record_relay_traffic($1::jsonb,$2)`, string(data), at.Add(time.Millisecond)).Scan(&count); err != nil || count != 0 {
				t.Fatal("tenant context admitted another tenant's traffic", err)
			}
		})
		check(t, b, at.Format("2006-01"), "21", "22", 0)
		var tables, backedUp int
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM pg_class WHERE relname IN ('relay_traffic_samples','relay_traffic_months') AND relnamespace='public'::regnamespace AND relrowsecurity AND relforcerowsecurity`).Scan(&tables); err != nil || tables != 2 {
			t.Fatal("traffic tables lost forced RLS", err)
		}
		if err := backup.QueryRowContext(ctx, `SELECT count(*) FROM relay_traffic_months WHERE device_id IN ($1,$2)`, a.device, b.device).Scan(&backedUp); err != nil || backedUp != 2 {
			t.Fatal("backup role cannot read both tenant facts", err)
		}
		withTenant(t, web, tenantA, func(tx *sql.Tx) {
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM relay_traffic_months WHERE device_id=$1`, b.device).Scan(&count); err != nil || count != 0 {
				t.Fatal("Web bypassed traffic RLS", err)
			}
		})
		withTenant(t, authz, tenantA, func(tx *sql.Tx) {
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM relay_traffic_samples WHERE device_id=$1`, b.device).Scan(&count); err != nil || count != 0 {
				t.Fatal("authz bypassed traffic sampling RLS", err)
			}
		})
		for _, test := range []struct {
			db    *sql.DB
			query string
		}{
			{web, `SELECT * FROM relay_traffic_samples`},
			{web, `UPDATE relay_traffic_months SET in_bytes=0 WHERE false`},
			{web, `SELECT record_relay_traffic('[]',clock_timestamp())`},
			{backup, `UPDATE relay_traffic_months SET out_bytes=0 WHERE false`},
		} {
			_, err := test.db.ExecContext(ctx, test.query)
			var failure *pgconn.PgError
			if !errors.As(err, &failure) || failure.Code != "42501" {
				t.Fatal("traffic role restriction failed")
			}
		}
	})
	t.Run("unknown_identity_does_not_create_device", func(t *testing.T) {
		f := makeDevice(t, tenantA)
		unknown := fixture{tenant: tenantA, subdomain: "unknown1"}
		if err := owner.QueryRowContext(ctx, `SELECT gen_random_uuid()`).Scan(&unknown.device); err != nil {
			t.Fatal(err)
		}
		at := current()
		record(t, at, sample(f, 1, 2), sample(unknown, 999, 999))
		empty(t, unknown)
		check(t, f, at.Format("2006-01"), "1", "2", 0)
	})
	t.Run("invalid_batch_is_atomic", func(t *testing.T) {
		f := makeDevice(t, tenantA)
		good := sample(f, 10, 20)
		negative := sample(f, -1, 2)
		for _, values := range [][]relaystate.TrafficSample{{negative}, {good, good}} {
			data, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			withTenant(t, authz, tenantA, func(tx *sql.Tx) {
				if _, err := tx.ExecContext(ctx, `SELECT record_relay_traffic($1::jsonb,$2)`, string(data), current()); err == nil {
					t.Fatal("invalid traffic batch was accepted")
				}
			})
			empty(t, f)
		}
		for _, at := range []time.Time{time.Now().Add(time.Minute), time.Now().Add(-2 * time.Minute)} {
			data, _ := json.Marshal([]relaystate.TrafficSample{good})
			withTenant(t, authz, tenantA, func(tx *sql.Tx) {
				if _, err := tx.ExecContext(ctx, `SELECT record_relay_traffic($1::jsonb,$2)`, string(data), at); err == nil {
					t.Fatal("unbounded traffic timestamp was accepted")
				}
			})
			empty(t, f)
		}
	})
	t.Run("busy_telemetry_tenant_skips_without_waiting", func(t *testing.T) {
		f := makeDevice(t, tenantA)
		at := current()
		lock, err := owner.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback()
		if _, err = lock.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('nethub:traffic:'||$1,0))`, f.tenant); err != nil {
			t.Fatal(err)
		}
		bounded, stop := context.WithTimeout(ctx, time.Second)
		err = storage.ObserveTraffic(bounded, at, []relaystate.TrafficSample{sample(f, 1, 2)})
		stop()
		if err != nil {
			t.Fatal("traffic advisory lock delayed sampling", err)
		}
		empty(t, f)
		if err = lock.Rollback(); err != nil {
			t.Fatal(err)
		}
		record(t, at.Add(time.Millisecond), sample(f, 1, 2))
		check(t, f, at.Format("2006-01"), "1", "2", 0)
	})
	if !t.Failed() {
		t.Log("Traffic SQL verified durable daily deltas, replay and reset handling, concurrent single accounting, month rollover, exact wide totals, retained removed-device facts, tenant/role fences and nonblocking telemetry without device or grant changes")
	}
}
