package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func testConsoleAudit(t *testing.T, ctx context.Context, owner, db *sql.DB) {
	t.Helper()
	// Keep fixture tenants until the enclosing disposable database is removed by
	// tests/postgres.sh, as with the other tenant-scoped integration fixtures.
	// Deleting their last local administrator would violate the product guard.
	newTenant := func() string {
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('Audit view fixture') RETURNING id`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	tenant, foreign := newTenant(), newTenant()
	user := func(scope, email, role string) string {
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,$2,$3,'isolated audit fixture hash') RETURNING id`, scope, email, role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	admin := user(tenant, "audit-admin@example.com", "admin")
	_ = user(tenant, "audit-backup-admin@example.com", "admin")
	member := user(tenant, "audit-member@example.com", "member")
	other := user(tenant, "audit-other@example.com", "member")
	foreignAdmin := user(foreign, "audit-foreign@example.com", "admin")
	device := func(actor string) string {
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO devices(tenant_id,owner_user_id,hostname,platform,device_secret_hash,subdomain,agent_protocol_version) VALUES($1,$2,'Audit fixture','opnsense','isolated audit fixture hash',$3,'1.5.0') RETURNING id`, tenant, actor, "audit-"+actor).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ownDevice, otherDevice := device(member), device(other)
	appendEntry := func(scope, kind string, actor *string, action string, target *string, payload string) string {
		t.Helper()
		tx, err := owner.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, scope); err != nil {
			t.Fatal(err)
		}
		var id string
		if err = tx.QueryRowContext(ctx, `SELECT append_audit($1,$2,$3,$4,$5::jsonb)`, kind, actor, action, target, payload).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return id
	}
	const sensitive = `{"source_ip":"198.51.100.9","secret":"audit-private-secret-sentinel","entry_hash":"audit-private-hash-sentinel","metadata":"audit-private-metadata-sentinel"}`
	ownAction := appendEntry(tenant, "user", &member, "auth.login", nil, `{"source_ip":"192.0.2.1"}`)
	enrolled := appendEntry(tenant, "user", &member, "device.enrolled", &ownDevice, `{}`)
	ownSystem := appendEntry(tenant, "system", nil, "device.fixture", &ownDevice, sensitive)
	deviceActor := appendEntry(tenant, "device", &ownDevice, "device.fixture", nil, sensitive)
	appendEntry(tenant, "user", &other, "device.enrolled", &otherDevice, `{}`)
	otherSystem := appendEntry(tenant, "system", nil, "device.fixture", &otherDevice, sensitive)
	account := appendEntry(tenant, "user", &admin, "user.updated", nil, `{"target_user_id":"`+member+`","source_ip":"198.51.100.9","role":"member","disabled":false}`)
	foreignEntry := appendEntry(foreign, "user", &foreignAdmin, "auth.login", nil, sensitive)
	repo := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}}
	read := func(actor string, query web.AuditQuery) web.AuditPage {
		t.Helper()
		page, err := repo.Audit(ctx, actor, query)
		if err != nil {
			t.Fatal("actual audit read failed", err)
		}
		raw, _ := json.Marshal(page)
		if strings.Contains(string(raw), "sentinel") || strings.Contains(string(raw), foreignEntry) {
			t.Fatal("audit projection leaked private data or another tenant")
		}
		return page
	}
	memberPage := read(member, web.AuditQuery{Limit: 200})
	want := map[string]bool{ownAction: true, enrolled: true, ownSystem: true, deviceActor: true, account: true}
	if len(memberPage.Items) != len(want) {
		t.Fatal("member did not receive exactly related audit entries")
	}
	for _, entry := range memberPage.Items {
		if !want[entry.ID] || (entry.ID != ownAction && entry.ClientIP != nil) {
			t.Fatal("member visibility or administrator/system IP redaction failed")
		}
	}
	if len(read(admin, web.AuditQuery{Limit: 200}).Items) != 7 {
		t.Fatal("administrator audit view omitted tenant entries")
	}
	if len(read(member, web.AuditQuery{Limit: 200, DeviceID: ownDevice}).Items) != 3 {
		t.Fatal("device filter lost device-actor events")
	}
	if _, err := repo.Audit(ctx, member, web.AuditQuery{Limit: 10, UserID: member}); !errors.Is(err, web.ErrForbidden) {
		t.Fatal("runtime role admitted a member actor filter")
	}
	seen := map[string]bool{}
	query := web.AuditQuery{Limit: 2}
	for {
		page := read(member, query)
		for _, entry := range page.Items {
			if seen[entry.ID] {
				t.Fatal("audit pagination repeated an entry")
			}
			seen[entry.ID] = true
		}
		if page.NextCursor == nil {
			break
		}
		query.Cursor = *page.NextCursor
	}
	if len(seen) != len(want) || seen[otherSystem] {
		t.Fatal("stable pagination crossed member visibility")
	}
	if _, err := owner.ExecContext(ctx, `DELETE FROM devices WHERE id=$1`, ownDevice); err != nil {
		t.Fatal(err)
	}
	if len(read(member, web.AuditQuery{Limit: 200}).Items) != len(want) {
		t.Fatal("removed-device history lost its recorded enrollment owner")
	}
	appendEntry(tenant, "user", &other, "device.enrolled", &ownDevice, `{}`)
	for _, entry := range read(member, web.AuditQuery{Limit: 200}).Items {
		if entry.ID == ownSystem || entry.ID == deviceActor {
			t.Fatal("ambiguous historical ownership granted device audit access")
		}
	}
	if _, err := owner.ExecContext(ctx, `UPDATE users SET role='member' WHERE id=$1`, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Audit(ctx, admin, web.AuditQuery{Limit: 10, UserID: member}); !errors.Is(err, web.ErrForbidden) {
		t.Fatal("demoted administrator retained the actor filter")
	}
	if _, err := owner.ExecContext(ctx, `UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1`, member); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Audit(ctx, member, web.AuditQuery{Limit: 10}); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("disabled account retained audit access")
	}
	t.Log("Actual runtime-role audit reads preserved tenant/member/removed-device scope, typed secret exclusion, IP redaction, stable pagination and live authority")
}
