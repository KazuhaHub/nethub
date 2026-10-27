package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresBoundaries(t *testing.T) {
	if os.Getenv("NETHUB_DATABASE_TEST") != "1" {
		t.Skip("run tests/postgres.sh for an isolated genuine PostgreSQL instance")
	}
	// The suite includes three real fifteen-second anomaly observations in the
	// compiled runtime, in addition to the existing SQL and refresh lock cases.
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	connect := func(role string) *sql.DB {
		t.Helper()
		db, err := OpenRole(ctx, DatabaseConfig{Host: "127.0.0.1", Port: 5432, Database: "nethub", PasswordFile: "/run/secrets/pg_" + role, SSLMode: "disable"}, role)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	owner, web, authz, backup := connect("nethub_owner"), connect("nethub_web"), connect("nethub_authz"), connect("nethub_backup")
	t.Run("platform_forward_migration", func(t *testing.T) {
		restore := legacyIssuerRoleFixture(t, ctx, owner)
		defer restore()
		testPlatformForwardMigration(t, ctx, owner, web, authz)
		if err := (&EnrollmentStore{DB: authz}).Health(ctx); err != nil {
			t.Fatal("disabled legacy device APIs require issuer role", err)
		}
	})
	for range 2 {
		if err := Migrate(ctx, owner); err != nil {
			var failure *pgconn.PgError
			if errors.As(err, &failure) {
				t.Logf("migration SQLSTATE=%s position=%d context=%s", failure.Code, failure.Position, failure.Where)
			}
			t.Fatal(err)
		}
	}
	t.Run("isolated_gui_issuer_role", func(t *testing.T) { testGUIIssuerRole(t, ctx, owner, web, authz) })
	var tenantA, tenantB string
	if err := owner.QueryRowContext(ctx, `SELECT id FROM tenants`).Scan(&tenantA); err != nil {
		t.Fatal(err)
	}
	if selected, err := SoleTenant(ctx, web); err != nil || selected != tenantA {
		t.Fatalf("single-tenant startup selection: %v", err)
	}
	var bootstrapID string
	t.Run("initial_admin_bootstrap", func(t *testing.T) { bootstrapID = testAdminBootstrap(t, ctx, owner, web, authz, tenantA) })
	if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('Integration B') RETURNING id`).Scan(&tenantB); err != nil {
		t.Fatal(err)
	}
	user := func(tenant, email, role string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,$2,$3,'fixture-only-hash') RETURNING id`, tenant, email, role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	adminA := user(tenantA, "admin-a@example.com", "admin")
	// Restore the existing boundary fixtures after testing the empty deployment.
	if _, err := owner.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, bootstrapID); err != nil {
		t.Fatal(err)
	}
	memberA, memberOther := user(tenantA, "member-a@example.com", "member"), user(tenantA, "other-a@example.com", "member")
	adminB := user(tenantB, "admin-b@example.com", "admin")
	device := func(tenant, actor, subdomain string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO devices(tenant_id,owner_user_id,platform,device_secret_hash,subdomain,agent_protocol_version) VALUES($1,$2,'opnsense','fixture-only-hash',$3,'fixture') RETURNING id`, tenant, actor, subdomain).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	deviceA := device(tenantA, memberA, "integration-a")
	device(tenantA, memberOther, "integration-other")
	deviceB := device(tenantB, adminB, "integration-b")
	txFor := func(db *sql.DB, tenant string) *sql.Tx {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { tx.Rollback() })
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		return tx
	}
	expectError := func(db *sql.DB, tenant, code, query string, args ...any) {
		t.Helper()
		tx := txFor(db, tenant)
		_, err := tx.ExecContext(ctx, query, args...)
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != code {
			t.Fatalf("expected SQLSTATE %s, got %v", code, err)
		}
		tx.Rollback()
	}
	t.Run("role_and_forced_RLS_shape", func(t *testing.T) {
		var count int
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM pg_roles WHERE rolname IN ('nethub_web','nethub_authz') AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole`).Scan(&count); err != nil || count != 2 {
			t.Fatalf("runtime role boundary: count=%d err=%v", count, err)
		}
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relname IN ('users','devices','enroll_tokens','sessions','audit_log','identity_providers','oidc_providers','saml_providers','user_identities','invites','device_access_grants','device_disconnect_requests') AND relrowsecurity AND relforcerowsecurity`).Scan(&count); err != nil || count != 12 {
			t.Fatalf("forced RLS: count=%d err=%v", count, err)
		}
		if err := Migrate(ctx, web); err == nil {
			t.Fatal("web could invoke migrations")
		}
	})
	t.Run("doctor_runtime_role_metadata", func(t *testing.T) { testReadinessRoles(t, ctx, owner, web, authz) })
	t.Run("tenant_and_member_visibility", func(t *testing.T) {
		connection, err := web.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		tx, err := connection.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenantA); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(id) FROM devices`).Scan(&count); err != nil || count != 2 {
			t.Fatalf("tenant A visibility: count=%d err=%v", count, err)
		}
		tx.Rollback()
		if err := connection.QueryRowContext(ctx, `SELECT count(id) FROM devices`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("tenant context leaked from transaction: count=%d err=%v", count, err)
		}
		for _, test := range []struct {
			actor string
			count int
		}{{memberA, 1}, {adminA, 2}, {adminB, 0}} {
			devices, err := ListDevices(ctx, web, tenantA, test.actor)
			if err != nil || len(devices) != test.count {
				t.Fatalf("actor device visibility: count=%d want=%d err=%v", len(devices), test.count, err)
			}
		}
	})
	t.Run("bounded_platform_identifiers", func(t *testing.T) {
		for _, platform := range []string{"opnsense", "openwrt", "vyos", "future-router", "a" + strings.Repeat("0", 31)} {
			tx := txFor(authz, tenantA)
			var got string
			if err := tx.QueryRowContext(ctx, `UPDATE devices SET platform=$1 WHERE id=$2 RETURNING platform`, platform, deviceA).Scan(&got); err != nil || got != platform {
				t.Fatalf("valid platform identifier: %v", err)
			}
			tx.Rollback()
		}
		for _, platform := range []string{"", "OpenWrt", "open_wrt", "1router", "a" + strings.Repeat("0", 32), "router\n", "routér"} {
			expectError(authz, tenantA, "23514", `UPDATE devices SET platform=$1 WHERE id=$2`, platform, deviceA)
		}
		expectError(web, tenantA, "42501", `UPDATE devices SET platform='vyos' WHERE id=$1`, deviceA)
	})
	t.Run("forbidden_identity_and_cross_process_access", func(t *testing.T) {
		for _, query := range []string{`SELECT device_secret_hash FROM devices`, `UPDATE devices SET subdomain='taken'`, `UPDATE devices SET owner_user_id=gen_random_uuid()`, `DELETE FROM devices`, `INSERT INTO devices DEFAULT VALUES`, `SELECT consume_enroll_token(decode(repeat('00',32),'hex'))`, `INSERT INTO device_access_grants DEFAULT VALUES`, `UPDATE device_disconnect_requests SET processed_at=now()`} {
			expectError(web, tenantA, "42501", query)
		}
		expectError(authz, tenantA, "42501", `SELECT * FROM users`)
		expectError(backup, tenantA, "42501", `UPDATE devices SET label='backup-write'`)
		expectError(web, tenantA, "23503", `INSERT INTO sessions(tenant_id,user_id,token_hash,csrf_hash,expires_at,ip,user_agent) VALUES($1,$2,decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),now()+interval '1 hour','192.0.2.1','test')`, tenantA, adminB)
		var count int
		if err := backup.QueryRowContext(ctx, `SELECT count(*) FROM devices`).Scan(&count); err != nil || count != 3 {
			t.Fatalf("backup bypass RLS read failed: count=%d err=%v", count, err)
		}
	})
	t.Run("single_use_enrollment_under_concurrency", func(t *testing.T) {
		hash := sha256.Sum256([]byte("integration single use token"))
		tx := txFor(web, tenantA)
		if _, err := tx.ExecContext(ctx, `INSERT INTO enroll_tokens(tenant_id,token_hash,created_by_user_id) VALUES($1,$2,$3)`, tenantA, hash[:], memberA); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		var successes atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				var tenant, actor string
				err := authz.QueryRowContext(ctx, `SELECT tenant_id,created_by_user_id FROM consume_enroll_token($1)`, hash[:]).Scan(&tenant, &actor)
				if err == nil && tenant == tenantA && actor == memberA {
					successes.Add(1)
				} else if !errors.Is(err, sql.ErrNoRows) {
					t.Errorf("token consumption: %v", err)
				}
			})
		}
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatalf("successful consumers: %d", successes.Load())
		}
	})
	t.Run("backup_dump_covers_both_tenants_without_writes", func(t *testing.T) {
		password, err := os.ReadFile("/run/secrets/pg_nethub_backup")
		if err != nil {
			t.Fatal(err)
		}
		directory := t.TempDir()
		passfile := filepath.Join(directory, "pgpass")
		if err := os.WriteFile(passfile, []byte("127.0.0.1:5432:nethub:nethub_backup:"+strings.TrimSpace(string(password))+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		dump := filepath.Join(directory, "backup.sql")
		command := exec.CommandContext(ctx, "pg_dump", "-h", "127.0.0.1", "-U", "nethub_backup", "-d", "nethub", "--no-owner", "--no-privileges", "-f", dump)
		command.Env = append(os.Environ(), "PGPASSFILE="+passfile)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("backup failed: %v %s", err, output)
		}
		content, err := os.ReadFile(dump)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{"Integration B", "admin-a@example.com", "admin-b@example.com", "integration-a", "integration-b"} {
			if !strings.Contains(string(content), marker) {
				t.Fatalf("backup omitted fixture %q", marker)
			}
		}
	})
	t.Run("expired_or_disabled_enrollment_is_rejected", func(t *testing.T) {
		for _, test := range []struct {
			name    string
			expired bool
		}{{"expired", true}, {"disabled-creator", false}} {
			hash := sha256.Sum256([]byte(test.name))
			query := `INSERT INTO enroll_tokens(tenant_id,token_hash,created_by_user_id) VALUES($1,$2,$3)`
			if test.expired {
				query = `INSERT INTO enroll_tokens(tenant_id,token_hash,created_by_user_id,created_at,expires_at) VALUES($1,$2,$3,now()-interval '20 minutes',now()-interval '5 minutes')`
			} else if _, err := owner.ExecContext(ctx, `UPDATE users SET disabled_at=now() WHERE id=$1`, memberOther); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.ExecContext(ctx, query, tenantA, hash[:], memberOther); err != nil {
				t.Fatal(err)
			}
			var tenant string
			if err := authz.QueryRowContext(ctx, `SELECT tenant_id FROM consume_enroll_token($1)`, hash[:]).Scan(&tenant); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("%s token was not rejected: %v", test.name, err)
			}
		}
		if _, err := owner.ExecContext(ctx, `UPDATE users SET disabled_at=NULL WHERE id=$1`, memberOther); err != nil {
			t.Fatal(err)
		}
		expectError(web, tenantA, "42501", `UPDATE enroll_tokens SET expires_at=now()+interval '1 day'`)
	})
	t.Run("scoped_explicit_open_and_cutoff", func(t *testing.T) {
		expectError(web, tenantA, "42501", `SELECT open_device($1,$2,'192.0.2.1')`, memberOther, deviceA)
		expectError(web, tenantA, "42501", `SELECT open_device($1,$2,'192.0.2.1')`, memberA, deviceB)
		expectError(web, tenantA, "22023", `SELECT open_device($1,$2,'192.0.2.0/24')`, memberA, deviceA)
		tx := txFor(web, tenantA)
		var expires time.Time
		if err := tx.QueryRowContext(ctx, `SELECT open_device($1,$2,'192.0.2.1')`, memberA, deviceA).Scan(&expires); err != nil || time.Until(expires) < 29*time.Minute || time.Until(expires) > 31*time.Minute {
			t.Fatalf("grant lifetime: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		expectError(web, tenantA, "42501", `SELECT request_device_disconnect($1,$2)`, memberA, deviceA)
	})
	t.Run("one_way_revocation", func(t *testing.T) {
		tx := txFor(web, tenantA)
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET revoked=true,revoked_at=now(),revoked_by_user_id=$1 WHERE id=$2`, memberA, deviceA); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		expectError(web, tenantA, "23514", `UPDATE devices SET revoked=false WHERE id=$1`, deviceA)
		expectError(authz, tenantA, "23514", `UPDATE devices SET revoked=false WHERE id=$1`, deviceA)
		request := txFor(web, tenantA)
		if _, err := request.ExecContext(ctx, `SELECT request_device_disconnect($1,$2)`, memberA, deviceA); err != nil {
			t.Fatal("revoked cutoff request refused", err)
		}
		if err := request.Commit(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("append_only_audit_chain", func(t *testing.T) {
		for range 2 {
			tx := txFor(web, tenantA)
			if _, err := tx.ExecContext(ctx, `SELECT append_audit('user',$1,'test',NULL,'{}'::jsonb)`, memberA); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		expectError(web, tenantA, "42501", `UPDATE audit_log SET action='rewritten'`)
		expectError(authz, tenantA, "42501", `DELETE FROM audit_log`)
		var linked bool
		if err := owner.QueryRowContext(ctx, `SELECT b.prev_hash=a.entry_hash FROM audit_log a JOIN audit_log b ON a.tenant_id=b.tenant_id AND b.sequence=a.sequence+1 WHERE a.tenant_id=$1`, tenantA).Scan(&linked); err != nil || !linked {
			t.Fatalf("audit chain: linked=%v err=%v", linked, err)
		}
	})
	t.Run("local_authentication_and_session_boundaries", func(t *testing.T) {
		actor := user(tenantA, "auth-member@example.com", "member")
		password := "a fixture passphrase used only by isolated tests"
		hash, err := auth.HashPassword(password)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = owner.ExecContext(ctx, `UPDATE users SET password_hash=$1 WHERE id=$2`, hash, actor); err != nil {
			t.Fatal(err)
		}
		storeA := &AuthStore{DB: web, Tenant: tenantA}
		service, err := auth.NewService(storeA, auth.Config{})
		if err != nil {
			t.Fatal(err)
		}
		ip := netip.MustParseAddr("192.0.2.1")
		login, err := service.Login(ctx, " AUTH-MEMBER@example.com ", password, ip, "test browser")
		if err != nil || login.User.ID != actor || login.User.Role != "member" {
			t.Fatalf("login: user=%s err=%v", login.User.ID, err)
		}
		if _, err = service.Login(ctx, "auth-member@example.com", "wrong", ip, "test"); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("wrong password: %v", err)
		}
		if _, err = service.Login(ctx, "missing@example.com", password, ip, "test"); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("unknown user: %v", err)
		}
		var tokenDigest, csrfDigest []byte
		if err = owner.QueryRowContext(ctx, `SELECT token_hash,csrf_hash FROM sessions WHERE user_id=$1`, actor).Scan(&tokenDigest, &csrfDigest); err != nil {
			t.Fatal(err)
		}
		rawToken, err := base64.RawURLEncoding.DecodeString(login.Token)
		if err != nil {
			t.Fatal(err)
		}
		wantTokenHash := sha256.Sum256(rawToken)
		wantCSRFHash := sha256.Sum256([]byte(login.CSRFToken))
		if !bytes.Equal(tokenDigest, wantTokenHash[:]) || !bytes.Equal(csrfDigest, wantCSRFHash[:]) || bytes.Equal(tokenDigest, rawToken) {
			t.Fatal("raw session material persisted")
		}
		current, err := service.Authenticate(ctx, login.Token)
		if err != nil || current.CSRFToken != login.CSRFToken || !auth.CheckCSRF(current, login.CSRFToken) || auth.CheckCSRF(current, login.Token) {
			t.Fatalf("session or CSRF: %v", err)
		}
		if _, err = service.Authenticate(ctx, login.CSRFToken); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatal("CSRF value accepted as session bearer")
		}
		storeB := &AuthStore{DB: web, Tenant: tenantB}
		if _, err = storeB.LookupSession(ctx, tokenDigest, 30*time.Minute); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("session crossed tenant: %v", err)
		}
		if _, err = storeB.LookupSessionPassive(ctx, tokenDigest, 30*time.Minute); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatal("passive session lookup crossed tenant")
		}
		if _, err = service.Authenticate(ctx, login.Token); err != nil {
			t.Fatal(err)
		}
		var activityBefore, activityAfter time.Time
		if err = owner.QueryRowContext(ctx, `SELECT last_seen_at FROM sessions WHERE token_hash=$1`, tokenDigest).Scan(&activityBefore); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1200 * time.Millisecond)
		if passive, lookupError := storeA.LookupSessionPassive(ctx, tokenDigest, 3*time.Second); lookupError != nil || passive.ID != actor {
			t.Fatal("passive read rejected an unexpired session")
		}
		if err = owner.QueryRowContext(ctx, `SELECT last_seen_at FROM sessions WHERE token_hash=$1`, tokenDigest).Scan(&activityAfter); err != nil || !activityAfter.Equal(activityBefore) {
			t.Fatal("passive lookup refreshed idle activity")
		}
		time.Sleep(2100 * time.Millisecond)
		for _, lookup := range []func(context.Context, []byte, time.Duration) (auth.SessionRecord, error){storeA.LookupSessionPassive, storeA.LookupSession} {
			if _, err = lookup(ctx, tokenDigest, 3*time.Second); !errors.Is(err, auth.ErrUnauthenticated) {
				t.Fatal("background or active lookup revived a naturally idle-expired session")
			}
		}
		t.Log("Passive session lookup preserved last_seen_at and natural idle expiry; active lookup could not revive it")
		if _, err = owner.ExecContext(ctx, `UPDATE users SET role='admin' WHERE id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		current, err = service.Authenticate(ctx, login.Token)
		if err != nil || current.User.Role != "admin" {
			t.Fatal("session retained stale role")
		}
		if passive, passiveError := service.AuthenticatePassive(ctx, login.Token); passiveError != nil || passive.User.Role != "admin" {
			t.Fatal("passive lookup retained a stale role")
		}
		// Return to member before disable so last-admin protection is independent.
		if _, err = owner.ExecContext(ctx, `UPDATE users SET role='member',disabled_at=now() WHERE id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err = service.Authenticate(ctx, login.Token); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatal("disabled account retained a live session")
		}
		if _, err = service.AuthenticatePassive(ctx, login.Token); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatal("passive lookup accepted a disabled account")
		}
		if _, err = service.Login(ctx, "auth-member@example.com", password, ip, "test"); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatal("disabled account logged in")
		}
		if _, err = owner.ExecContext(ctx, `UPDATE users SET disabled_at=NULL WHERE id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err = owner.ExecContext(ctx, `UPDATE users SET password_hash=NULL WHERE id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err = service.Login(ctx, "auth-member@example.com", password, ip, "test"); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatal("SSO-only account logged in with local credentials")
		}
		if _, err = owner.ExecContext(ctx, `UPDATE users SET password_hash='malformed-fixture' WHERE id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err = service.Login(ctx, "auth-member@example.com", password, ip, "test"); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatal("malformed password hash accepted")
		}
		if _, err = owner.ExecContext(ctx, `UPDATE users SET password_hash=$1 WHERE id=$2`, hash, actor); err != nil {
			t.Fatal(err)
		}
		candidate, err := storeA.PasswordCandidate(ctx, "auth-member@example.com")
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		record := auth.SessionRecord{TokenHash: bytes.Repeat([]byte{1}, 32), CSRFHash: bytes.Repeat([]byte{2}, 32), CreatedAt: now, ExpiresAt: now.Add(time.Hour), IP: ip, UserAgent: "fixture"}
		if _, err = owner.ExecContext(ctx, `UPDATE users SET password_hash='changed-fixture' WHERE id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err = storeA.CreateSession(ctx, candidate, record); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatal("stale password check created a session")
		}
		if _, err = owner.ExecContext(ctx, `UPDATE users SET password_hash=$1,disabled_at=now() WHERE id=$2`, hash, actor); err != nil {
			t.Fatal(err)
		}
		if _, err = storeA.CreateSession(ctx, candidate, record); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatal("disabled-during-verification user created a session")
		}
		if _, err = owner.ExecContext(ctx, `UPDATE users SET disabled_at=NULL WHERE id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err = owner.ExecContext(ctx, `UPDATE sessions SET last_seen_at=now()-interval '31 minutes' WHERE user_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err = service.Authenticate(ctx, login.Token); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatal("idle-expired session accepted")
		}
		if _, err = owner.ExecContext(ctx, `UPDATE sessions SET last_seen_at=now(),expires_at=now()-interval '1 second' WHERE user_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err = service.Authenticate(ctx, login.Token); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatal("absolute-expired session accepted")
		}
		// Admission must use the clock after either row-lock wait, rather than
		// the statement start time at which this session was still valid.
		for _, lookup := range []func(context.Context, []byte, time.Duration) (auth.SessionRecord, error){storeA.LookupSession, storeA.LookupSessionPassive} {
			for _, lockQuery := range []string{`SELECT id FROM users WHERE id=$1 FOR UPDATE`, `SELECT id FROM sessions WHERE user_id=$1 FOR UPDATE`} {
				if _, err = owner.ExecContext(ctx, `UPDATE sessions SET last_seen_at=clock_timestamp(),expires_at=clock_timestamp()+interval '150 milliseconds' WHERE user_id=$1`, actor); err != nil {
					t.Fatal(err)
				}
				blocker, err := owner.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Rollback()
				if _, err = blocker.ExecContext(ctx, lockQuery, actor); err != nil {
					t.Fatal(err)
				}
				lookupResult := make(chan error, 1)
				go func() { _, err := lookup(ctx, tokenDigest, 30*time.Minute); lookupResult <- err }()
				waiting := false
				for range 100 {
					var blocked int
					if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='transactionid' AND NOT granted`).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if blocked > 0 {
						waiting = true
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !waiting {
					t.Fatal("lookup did not reach the row lock")
				}
				if _, err = owner.ExecContext(ctx, `SELECT pg_sleep(0.2)`); err != nil {
					t.Fatal(err)
				}
				if err = blocker.Commit(); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-lookupResult:
					if !errors.Is(err, auth.ErrUnauthenticated) {
						t.Fatalf("accepted expiry during lock wait: %v", err)
					}
				case <-ctx.Done():
					t.Fatal("blocked session lookup did not finish")
				}
			}
		}
		t.Log("Active and passive session lookups rejected expiry after both real row-lock waits")
		if _, err = owner.ExecContext(ctx, `UPDATE sessions SET last_seen_at=clock_timestamp(),expires_at=clock_timestamp()+interval '1 hour' WHERE user_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err = service.Authenticate(ctx, login.Token); err != nil {
			t.Fatal("logout precondition session is not active")
		}
		if err = service.Logout(ctx, login.Token, ip); err != nil {
			t.Fatal(err)
		}
		if _, err = service.Authenticate(ctx, login.Token); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatal("logged-out session accepted")
		}
		if _, err = (&AuthStore{DB: authz, Tenant: tenantA}).PasswordCandidate(ctx, "auth-member@example.com"); err == nil {
			t.Fatal("authz could read console credentials")
		}
	})
	t.Run("last_local_admin_survives_concurrent_disable", func(t *testing.T) {
		second := user(tenantA, "admin-second@example.com", "admin")
		var successes atomic.Int32
		var wg sync.WaitGroup
		for _, actor := range []string{adminA, second} {
			wg.Go(func() {
				tx, err := web.BeginTx(ctx, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer tx.Rollback()
				_, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenantA)
				if err == nil {
					_, err = tx.ExecContext(ctx, `UPDATE users SET disabled_at=now() WHERE id=$1`, actor)
				}
				if err == nil {
					err = tx.Commit()
				}
				if err == nil {
					successes.Add(1)
					return
				}
				var pgerr *pgconn.PgError
				if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
					t.Errorf("admin disable: %v", err)
				}
			})
		}
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatalf("successful disables: %d", successes.Load())
		}
	})
	t.Run("console_HTTP_with_real_database", func(t *testing.T) { testConsoleHTTP(t, ctx, owner, web, authz, tenantA, tenantB) })
	t.Run("relay_traffic_accounting", func(t *testing.T) { testRelayTraffic(t, ctx, owner, authz, web, backup, tenantA, tenantB) })
	t.Run("traffic_console_and_warnings", func(t *testing.T) { testTrafficConsole(t, ctx, owner, authz, web, backup) })
	t.Run("explicit_device_access_grants", func(t *testing.T) { testExplicitDeviceAccess(t, ctx, owner, web, authz, tenantA, tenantB) })
	t.Run("authenticated_device_lifecycle", func(t *testing.T) { testDeviceLifecycle(t, ctx, owner, authz, web) })
	// Its final trust-history fixture changes deployment-global public state;
	// bootstrap-only lifecycle fixtures must run before that explicit rotation.
	t.Run("atomic_device_enrollment", func(t *testing.T) { testAtomicEnrollment(t, ctx, owner, authz, web, tenantA, tenantB) })
	t.Run("console_user_administration", func(t *testing.T) { testConsoleUsers(t, ctx, owner, web) })
	t.Run("console_invitations", func(t *testing.T) { testConsoleInvitations(t, ctx, owner, web) })
	t.Run("console_oidc_providers", func(t *testing.T) { testConsoleOIDCProviders(t, ctx, owner, web) })
	t.Run("console_saml_providers", func(t *testing.T) { testConsoleSAMLProviders(t, ctx, owner, web) })
	t.Run("oidc_browser_admission", func(t *testing.T) { testOIDCBrowserAdmission(t, ctx, owner, web, authz, backup) })
	t.Run("saml_replay_protection", func(t *testing.T) { testSAMLReplayProtection(t, ctx, owner, web, authz, backup) })
	t.Run("saml_browser_admission", func(t *testing.T) { testSAMLBrowserAdmission(t, ctx, owner, web, authz, backup) })
}
