package store

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

func testRevocationSnapshot(t *testing.T, f *enrollmentFixture, tenantA, tenantB string) {
	t.Helper()
	first, _, _ := f.fresh(t, tenantA)
	a, err := f.repository.Register(f.ctx, first, f.issue)
	if err != nil {
		t.Fatal(err)
	}
	second, _, _ := f.fresh(t, tenantB)
	b, err := f.repository.Register(f.ctx, second, f.issue)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := relayhook.NewRevocationCache(&RelayStore{DB: f.repository.DB}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil || cache.Refresh(f.ctx) != nil {
		t.Fatal("initial tenant-scoped snapshot failed", err)
	}
	identityA := protocol.ClaimPayload{TenantID: tenantA, DeviceID: a.ID}
	identityB := protocol.ClaimPayload{TenantID: tenantB, DeviceID: b.ID}
	if cache.AuthorizePing(identityA) != nil || cache.AuthorizePing(identityB) != nil {
		t.Fatal("active identities were cached as revoked")
	}
	if _, err = f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if cache.AuthorizePing(identityA) != nil {
		t.Fatal("Ping did not use its last in-memory snapshot")
	}
	if cache.Refresh(f.ctx) != nil || !errors.Is(cache.AuthorizePing(identityA), relayhook.ErrDenied) || cache.AuthorizePing(identityB) != nil {
		t.Fatal("tenant-scoped revocation was not published correctly")
	}
	if _, err = f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, b.ID); err != nil {
		t.Fatal(err)
	}
	if cache.Refresh(f.ctx) != nil || !errors.Is(cache.AuthorizePing(identityB), relayhook.ErrDenied) {
		t.Fatal("second tenant revocation was omitted")
	}
	blocker, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(f.ctx, `LOCK TABLE devices IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 100*time.Millisecond)
	started := time.Now()
	err = cache.Refresh(ctx)
	cancel()
	if !errors.Is(err, relayhook.ErrUnavailable) || time.Since(started) > time.Second {
		t.Fatal("real snapshot lock wait was not bounded", err)
	}
	if !errors.Is(cache.AuthorizePing(identityA), relayhook.ErrDenied) || !errors.Is(cache.AuthorizePing(identityB), relayhook.ErrDenied) {
		t.Fatal("SQL timeout replaced the last-good revocation set")
	}
	if err = blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	var leaked int
	if err = f.repository.DB.QueryRowContext(f.ctx, `SELECT count(*) FROM devices`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("snapshot tenant context escaped its transaction", err)
	}
	t.Log("Revocation snapshot passed real two-tenant updates, memory-only stale interval, bounded SQL table-lock failure, retained denials and transaction-local RLS scope")
}
