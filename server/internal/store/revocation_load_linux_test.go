package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

// This runs last in the disposable PostgreSQL harness. Immutable rotation rows
// remain until that harness destroys its owned container and volume.
func TestRevocationSnapshotLoad(t *testing.T) {
	if os.Getenv("NETHUB_DATABASE_TEST") != "1" || os.Getenv("NETHUB_REVOCATION_LOAD") != "1" {
		t.Skip("run the isolated PostgreSQL harness with NETHUB_REVOCATION_LOAD=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	open := func(role string) *sql.DB {
		db, err := OpenRole(ctx, DatabaseConfig{Host: "127.0.0.1", Port: 5432, Database: "nethub", PasswordFile: "/run/secrets/pg_" + role, SSLMode: "disable"}, role)
		if err != nil {
			t.Fatal("load database role unavailable", err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	owner, authz := open("nethub_owner"), open("nethub_authz")
	exec := func(query string, args ...any) {
		if _, err := owner.ExecContext(ctx, query, args...); err != nil {
			t.Fatal("load fixture mutation failed", err)
		}
	}
	count := func(query string) int {
		var n int
		if err := owner.QueryRowContext(ctx, query).Scan(&n); err != nil {
			t.Fatal("load fixture count failed", err)
		}
		return n
	}
	baselineRevoked := count("SELECT count(*) FROM devices WHERE revoked")
	baselineRotated := count("SELECT count(DISTINCT (tenant_id,device_id)) FROM device_rotations")
	baselineTenants := count("SELECT count(*) FROM tenants")
	if baselineRevoked >= 1000 || baselineRotated >= 1000 || baselineTenants >= 1024 {
		t.Fatal("unexpected baseline cannot establish the exact load cases")
	}
	var tenant, user string
	if err := owner.QueryRowContext(ctx, "INSERT INTO tenants(name) VALUES('Revocation load fixture') RETURNING id").Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRowContext(ctx, "INSERT INTO users(tenant_id,email,role) VALUES($1,'load@example.com','member') RETURNING id", tenant).Scan(&user); err != nil {
		t.Fatal(err)
	}
	// Only this disposable database receives synthetic rows. No enrollment or
	// signed claims are manufactured, and no live-client capacity is inferred.
	exec(`INSERT INTO devices(tenant_id,owner_user_id,hostname,platform,device_secret_hash,subdomain,agent_protocol_version,domain_claim_issued_at)
	 SELECT $1,$2,CASE WHEN n<=$3 THEN 'Load revoked fixture' ELSE 'Load rotated fixture' END,'opnsense','$argon2id$load-fixture-only-'||repeat('x',64),'load-'||gen_random_uuid()::text,'1.6.0',date_trunc('microseconds',statement_timestamp())
	 FROM generate_series(1,$3*2) AS n`, tenant, user, relayhook.MaxRevocations)
	var active, revoked string
	if err := owner.QueryRowContext(ctx, "SELECT min(id::text) FILTER(WHERE hostname='Load revoked fixture'),max(id::text) FILTER(WHERE hostname='Load rotated fixture') FROM devices WHERE tenant_id=$1", tenant).Scan(&revoked, &active); err != nil {
		t.Fatal(err)
	}
	var rotated string
	var issuedFloor time.Time
	if err := owner.QueryRowContext(ctx, "SELECT id,domain_claim_issued_at FROM devices WHERE tenant_id=$1 AND hostname='Load rotated fixture' ORDER BY id LIMIT 1", tenant).Scan(&rotated, &issuedFloor); err != nil {
		t.Fatal(err)
	}
	metrics := []map[string]any{}
	var lastGood *relayhook.RevocationCache
	measure := func(name string, expectedRevoked, expectedRotated, tenants int) {
		t.Helper()
		cache, err := relayhook.NewRevocationCache(&RelayStore{DB: authz}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		var before, after syscall.Rusage
		if syscall.Getrusage(syscall.RUSAGE_SELF, &before) != nil {
			t.Fatal("load CPU baseline unavailable")
		}
		var memoryBefore, memoryAfter runtime.MemStats
		runtime.ReadMemStats(&memoryBefore)
		started := time.Now()
		err = cache.Refresh(ctx)
		elapsed := time.Since(started)
		runtime.ReadMemStats(&memoryAfter)
		if syscall.Getrusage(syscall.RUSAGE_SELF, &after) != nil {
			t.Fatal("load CPU observation unavailable")
		}
		cpu := func(value syscall.Rusage) int64 { return value.Utime.Nano() + value.Stime.Nano() }
		record := map[string]any{"case": name, "revoked_rows": expectedRevoked, "rotation_floors": expectedRotated, "tenants": tenants,
			"refresh_us": elapsed.Microseconds(), "process_CPU_us": (cpu(after) - cpu(before)) / 1000, "allocated_bytes": memoryAfter.TotalAlloc - memoryBefore.TotalAlloc,
			"refresh_succeeded": err == nil, "refresh_budget_ms": relayhook.RevocationBudget.Milliseconds(), "live_client_capacity_accepted": false}
		metrics = append(metrics, record)
		defer func() { raw, _ := json.Marshal(record); t.Log("Actual SQL revocation load " + string(raw)) }()
		if err != nil {
			t.Error("actual SQL snapshot did not meet the candidate refresh budget", name)
			return
		}
		lastGood = cache
		known := protocol.ClaimPayload{TenantID: tenant, DeviceID: revoked}
		unknown := protocol.ClaimPayload{TenantID: tenant, DeviceID: active, IssuedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")}
		oldClaim := protocol.ClaimPayload{TenantID: tenant, DeviceID: rotated, IssuedAt: issuedFloor.UTC().Add(-time.Microsecond).Format("2006-01-02T15:04:05.000000Z")}
		started = time.Now()
		for range 10000 {
			if !errors.Is(cache.AuthorizePing(known), relayhook.ErrDenied) {
				t.Fatal("load lost a known denial")
			}
			if cache.AuthorizePing(unknown) != nil {
				t.Fatal("load falsely denied an unrelated current identity")
			}
			if !errors.Is(cache.AuthorizePing(oldClaim), relayhook.ErrDenied) {
				t.Fatal("load lost a retained claim floor")
			}
		}
		record["memory_predicate_triplets"] = 10000
		record["memory_predicate_us"] = time.Since(started).Microseconds()
		var leaked int
		if err := authz.QueryRowContext(ctx, "SELECT count(*) FROM devices").Scan(&leaked); err != nil || leaked != 0 {
			t.Fatal("load leaked a tenant transaction context")
		}
	}
	for _, size := range []int{1000, 10000, relayhook.MaxRevocations} {
		exec(`INSERT INTO device_rotations(tenant_id,device_id,operation_id,candidate_digest,credential_hash,issued_at,relay_ca_pem)
 SELECT tenant_id,id,gen_random_uuid(),decode(repeat('00',32),'hex'),device_secret_hash,domain_claim_issued_at,'fixture public CA'
	 FROM devices d WHERE tenant_id=$1 AND hostname='Load rotated fixture' AND NOT EXISTS(SELECT FROM device_rotations r WHERE r.tenant_id=d.tenant_id AND r.device_id=d.id)
 ORDER BY id LIMIT $2`, tenant, size-count("SELECT count(DISTINCT (tenant_id,device_id)) FROM device_rotations"))
		exec(`UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id IN
	 (SELECT id FROM devices WHERE tenant_id=$1 AND hostname='Load revoked fixture' AND NOT revoked ORDER BY id LIMIT $2)`, tenant, size-count("SELECT count(*) FROM devices WHERE revoked"))
		if count("SELECT count(*) FROM devices WHERE revoked") != size || count("SELECT count(DISTINCT (tenant_id,device_id)) FROM device_rotations") != size {
			t.Fatal("load did not establish exact snapshot row counts")
		}
		measure("row-scaling", size, size, baselineTenants+1)
	}
	exec("INSERT INTO tenants(name) SELECT 'Empty load tenant' FROM generate_series(1,$1)", 1024-count("SELECT count(*) FROM tenants"))
	if count("SELECT count(*) FROM tenants") != 1024 {
		t.Fatal("exact tenant bound not established")
	}
	measure("maximum-row-and-tenant-bounds", relayhook.MaxRevocations, relayhook.MaxRevocations, 1024)
	if len(metrics) != 4 {
		t.Fatal("load cases omitted")
	}
	exec("INSERT INTO tenants(name) VALUES('Over-bound load tenant')")
	if count("SELECT count(*) FROM tenants") != 1025 {
		t.Fatal("tenant overflow fixture missing")
	}
	if lastGood == nil {
		t.Fatal("no successful snapshot retained for overflow refusal")
	}
	started := time.Now()
	if !errors.Is(lastGood.Refresh(ctx), relayhook.ErrUnavailable) || time.Since(started) > relayhook.RevocationBudget+250*time.Millisecond {
		t.Fatal("actual tenant overflow was not refused within the dependency bound")
	}
	if !errors.Is(lastGood.AuthorizePing(protocol.ClaimPayload{TenantID: tenant, DeviceID: revoked}), relayhook.ErrDenied) {
		t.Fatal("tenant overflow lost the last-good denial")
	}
	t.Log("Actual 1,025-tenant overflow refused with the prior known denial retained")
	t.Log("Snapshot SQL/predicate observations do not establish signed HTTP Ping throughput, frp control continuity, console/public cutoff or supported online fleet capacity")
}
