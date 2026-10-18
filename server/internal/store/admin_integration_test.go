package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

func testAdminBootstrap(t *testing.T, ctx context.Context, owner, web, authz *sql.DB, tenant string) string {
	t.Helper()
	password := "an initial administrator fixture passphrase"
	for _, db := range []*sql.DB{web, authz} {
		if err := CreateInitialAdmin(ctx, db, "bootstrap@example.com", password); err == nil {
			t.Fatal("runtime role bootstrapped admin")
		}
	}
	if _, err := owner.ExecContext(ctx, `ALTER TABLE audit_log ADD CONSTRAINT fixture_reject_bootstrap CHECK (action<>'admin.bootstrap')`); err != nil {
		t.Fatal(err)
	}
	if err := CreateInitialAdmin(ctx, owner, "bootstrap@example.com", password); err == nil {
		t.Fatal("bootstrap ignored audit failure")
	}
	var users, admins int
	if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&users); err != nil || users != 0 {
		t.Fatal("audit failure left account behind")
	}
	if err := owner.QueryRowContext(ctx, `SELECT local_admin_count FROM tenants WHERE id=$1`, tenant).Scan(&admins); err != nil || admins != 0 {
		t.Fatal("audit failure left local-admin counter")
	}
	if _, err := owner.ExecContext(ctx, `ALTER TABLE audit_log DROP CONSTRAINT fixture_reject_bootstrap`); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			err := CreateInitialAdmin(ctx, owner, "Bootstrap@Example.COM", password)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrAlreadyInitialized) {
				t.Errorf("bootstrap: %v", err)
			}
		})
	}
	workers.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent initial administrators=%d", successes.Load())
	}
	var id, email, role, hash string
	if err := owner.QueryRowContext(ctx, `SELECT id,email,role,password_hash FROM users`).Scan(&id, &email, &role, &hash); err != nil {
		t.Fatal(err)
	}
	if email != "bootstrap@example.com" || role != "admin" || !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatal("bootstrap account shape invalid")
	}
	if valid, err := auth.VerifyPassword(hash, password); err != nil || !valid {
		t.Fatal("bootstrap password did not verify")
	}
	if err := owner.QueryRowContext(ctx, `SELECT local_admin_count FROM tenants WHERE id=$1`, tenant).Scan(&admins); err != nil || admins != 1 {
		t.Fatal("bootstrap admin counter incorrect")
	}
	if err := CreateInitialAdmin(ctx, owner, "different@example.com", password); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatal("repeat bootstrap accepted")
	}
	service, err := auth.NewService(&AuthStore{DB: web, Tenant: tenant}, auth.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	login, err := service.Login(ctx, email, password, ip, "bootstrap fixture")
	if err != nil || login.User.ID != id {
		t.Fatal("created admin cannot sign in")
	}
	if err = service.Logout(ctx, login.Token, ip); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := owner.QueryRowContext(ctx, `SELECT payload::text FROM audit_log WHERE action='admin.bootstrap' AND actor_id=$1`, id).Scan(&payload); err != nil || strings.Contains(payload, password) || strings.Contains(payload, hash) || !strings.Contains(payload, "local_cli") {
		t.Fatal("invalid bootstrap audit")
	}
	return id
}
