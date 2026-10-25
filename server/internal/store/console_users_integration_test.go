package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func testConsoleUsers(t *testing.T, ctx context.Context, owner, db *sql.DB) {
	t.Helper()
	var tenant, foreignTenant string
	for _, p := range []*string{&tenant, &foreignTenant} {
		if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('user administration fixture') RETURNING id`).Scan(p); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := auth.HashPassword("isolated administration fixture password")
	if err != nil {
		t.Fatal(err)
	}
	create := func(scope, email, role string, password *string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,$2,$3,$4) RETURNING id`, scope, email, role, password).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	admin := create(tenant, "users-admin@example.com", "admin", &hash)
	otherAdmin := create(tenant, "users-other-admin@example.com", "admin", &hash)
	ssoAdmin := create(tenant, "users-sso-admin@example.com", "admin", nil)
	member := create(tenant, "users-member@example.com", "member", &hash)
	foreign := create(foreignTenant, "users-foreign@example.com", "admin", &hash)
	var provider string
	if err = owner.QueryRowContext(ctx, `INSERT INTO identity_providers(tenant_id,kind,slug,display_name) VALUES($1,'oidc','staff','Staff') RETURNING id`, tenant).Scan(&provider); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ExecContext(ctx, `INSERT INTO user_identities(tenant_id,user_id,provider_id,protocol,issuer,subject,email_at_link) VALUES($1,$2,$3,'oidc','https://idp.example.com','opaque-user-fixture','users-member@example.com')`, tenant, member, provider); err != nil {
		t.Fatal(err)
	}
	repo := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}}
	ip := netip.MustParseAddr("::ffff:192.0.2.177")
	flag := func(v bool) *bool { return &v }
	role := func(v string) *string { return &v }
	if _, err = repo.Users(ctx, member, web.UserQuery{Limit: 10}); !errors.Is(err, web.ErrForbidden) {
		t.Fatal("member listed users", err)
	}
	if _, err = repo.Users(ctx, foreign, web.UserQuery{Limit: 10}); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("foreign actor listed users", err)
	}
	seen := map[string]bool{}
	cursor := ""
	for {
		page, e := repo.Users(ctx, admin, web.UserQuery{Limit: 1, AfterID: cursor})
		if e != nil || len(page.Items) != 1 {
			t.Fatal("user pagination", e)
		}
		u := page.Items[0]
		if seen[u.ID] || u.ID == foreign || u.Identities == nil {
			t.Fatal("user projection leaked or duplicated identity")
		}
		seen[u.ID] = true
		if u.HasPassword == (u.ID == ssoAdmin) {
			t.Fatal("incorrect password availability projection")
		}
		if u.ID == member && (len(u.Identities) != 1 || u.Identities[0].ProviderSlug != "staff" || u.Identities[0].LinkedAt.IsZero()) {
			t.Fatal("identity projection missing")
		}
		encoded, e := json.Marshal(u)
		if e != nil || strings.Contains(string(encoded), hash) || strings.Contains(string(encoded), "opaque-user-fixture") || strings.Contains(string(encoded), "https://idp.example.com") {
			t.Fatal("user projection exposed credential/identity material", e)
		}
		if page.NextCursor == nil {
			break
		}
		decoded, e := base64.RawURLEncoding.DecodeString(*page.NextCursor)
		if e != nil {
			t.Fatal(e)
		}
		cursor = string(decoded)
	}
	if len(seen) != 4 {
		t.Fatal("user pagination lost rows", len(seen))
	}
	for _, target := range []string{foreign, "00000000-0000-4000-8000-000000000000"} {
		if _, err = repo.UpdateUser(ctx, admin, target, web.UserPatch{Disabled: flag(true)}, ip); !errors.Is(err, web.ErrUserUnavailable) {
			t.Fatal("foreign/missing user mutation", err)
		}
	}
	if _, err = repo.UpdateUser(ctx, member, otherAdmin, web.UserPatch{Disabled: flag(true)}, ip); !errors.Is(err, web.ErrForbidden) {
		t.Fatal("member disabled administrator", err)
	}
	candidate, err := repo.PasswordCandidate(ctx, "users-member@example.com")
	if err != nil {
		t.Fatal(err)
	}
	token := sha256.Sum256([]byte("user administration session"))
	csrf := sha256.Sum256([]byte("user administration CSRF"))
	now := time.Now().UTC()
	record := auth.SessionRecord{TokenHash: token[:], CSRFHash: csrf[:], CreatedAt: now, ExpiresAt: now.Add(time.Hour), IP: ip, UserAgent: "user management integration"}
	if _, err = repo.CreateSession(ctx, candidate, record); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.UpdateUser(ctx, admin, member, web.UserPatch{Role: role("admin")}, ip); err != nil {
		t.Fatal(err)
	}
	if session, e := repo.LookupSession(ctx, token[:], time.Hour); e != nil || session.Role != "admin" {
		t.Fatal("session retained stale role", e)
	}
	if _, err = repo.UpdateUser(ctx, admin, member, web.UserPatch{Role: role("member"), Disabled: flag(true)}, ip); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.LookupSession(ctx, token[:], time.Hour); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("disabled session survived", err)
	}
	var count int
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1`, member).Scan(&count); err != nil || count != 0 {
		t.Fatal("disable retained sessions", err)
	}
	if _, err = repo.UpdateUser(ctx, admin, member, web.UserPatch{Disabled: flag(false)}, ip); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.LookupSessionPassive(ctx, token[:], time.Hour); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("reenable revived old session", err)
	}
	if _, err = repo.CreateSession(ctx, candidate, record); err != nil {
		t.Fatal(err)
	}
	// Failure at either append must restore the account, session and prior audit.
	defer owner.ExecContext(ctx, `DROP TRIGGER IF EXISTS reject_user_update_audit ON audit_log; DROP FUNCTION IF EXISTS reject_user_update_audit()`)
	for _, action := range []string{"user.updated", "auth.sessions_revoked"} {
		if _, err = owner.ExecContext(ctx, `CREATE FUNCTION reject_user_update_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='`+action+`' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_user_update_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_user_update_audit()`); err != nil {
			t.Fatal(err)
		}
		var before int
		if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1`, tenant).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err = repo.UpdateUser(ctx, admin, member, web.UserPatch{Disabled: flag(true)}, ip); err == nil {
			t.Fatal("audit failure accepted", action)
		}
		if session, e := repo.LookupSession(ctx, token[:], time.Hour); e != nil || session.Role != "member" {
			t.Fatal("audit failure changed account/session", e)
		}
		if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != before {
			t.Fatal("audit failure retained partial audit", err)
		}
		if _, err = owner.ExecContext(ctx, `DROP TRIGGER reject_user_update_audit ON audit_log; DROP FUNCTION reject_user_update_audit()`); err != nil {
			t.Fatal(err)
		}
	}
	// Two actual API-store transactions compete to remove the two local admins.
	done := make(chan error, 2)
	var wg sync.WaitGroup
	for _, target := range []string{admin, otherAdmin} {
		wg.Go(func() {
			_, e := repo.UpdateUser(ctx, ssoAdmin, target, web.UserPatch{Disabled: flag(true)}, ip)
			done <- e
		})
	}
	wg.Wait()
	close(done)
	good, denied := 0, 0
	for e := range done {
		if e == nil {
			good++
		} else if errors.Is(e, web.ErrLastLocalAdmin) {
			denied++
		} else {
			t.Fatal("concurrent admin mutation", e)
		}
	}
	if good != 1 || denied != 1 {
		t.Fatal("concurrent local-admin guard", good, denied)
	}
	var remaining string
	if err = owner.QueryRowContext(ctx, `SELECT id FROM users WHERE tenant_id=$1 AND role='admin' AND disabled_at IS NULL AND password_hash IS NOT NULL`, tenant).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.UpdateUser(ctx, remaining, ssoAdmin, web.UserPatch{Disabled: flag(true)}, ip); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.UpdateUser(ctx, remaining, remaining, web.UserPatch{Role: role("member")}, ip); !errors.Is(err, web.ErrLastAdmin) {
		t.Fatal("last administrator demoted", err)
	}
	// Wait for a real actor-row lock, then commit a demotion before admission.
	blocker, err := owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(ctx, `UPDATE users SET disabled_at=NULL WHERE id=$1`, ssoAdmin); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err = blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err = blocker.ExecContext(ctx, `UPDATE users SET role='member' WHERE id=$1`, ssoAdmin); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, e := repo.UpdateUser(ctx, ssoAdmin, member, web.UserPatch{Disabled: flag(true)}, ip)
		result <- e
	}()
	deadline := time.Now().Add(time.Second)
	for {
		var waiting bool
		if err = owner.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("user update never waited for actor lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err = blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-result; !errors.Is(err, web.ErrForbidden) {
		t.Fatal("demoted actor retained stale admin authority", err)
	}
	if _, err = repo.UpdateUser(ctx, remaining, ssoAdmin, web.UserPatch{Disabled: flag(true)}, ip); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Users(ctx, ssoAdmin, web.UserQuery{Limit: 1}); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("disabled actor listed users", err)
	}
	if _, err = repo.UpdateUser(ctx, ssoAdmin, member, web.UserPatch{Disabled: flag(true)}, ip); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("disabled actor mutated user", err)
	}
	if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='auth.sessions_revoked' AND payload->>'target_user_id'=$2 AND payload->>'source_ip'='192.0.2.177'`, tenant, member).Scan(&count); err != nil || count != 1 {
		t.Fatal("session-revocation audit scope", count, err)
	}
	t.Log("User administration verified paginated tenant/admin scope, current session roles, atomic disable/session revocation, no session revival, audit-failure rollback, competing local-admin changes and actor-lock demotion")
}
