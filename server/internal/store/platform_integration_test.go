package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
)

// Start with the actual previous migrations and an existing OPNsense device.
func testPlatformForwardMigration(t *testing.T, ctx context.Context, owner *sql.DB) {
	t.Helper()
	previous := fstest.MapFS{}
	for _, name := range []string{"00001_core.sql", "00002_scoped_operations.sql"} {
		data, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		previous[name] = &fstest.MapFile{Data: data}
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, owner, previous)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	var tenant, actor, device string
	if err := owner.QueryRowContext(ctx, `SELECT id FROM tenants`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role) VALUES($1,'migration@example.com','member') RETURNING id`, tenant).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRowContext(ctx, `INSERT INTO devices(tenant_id,owner_user_id,platform,device_secret_hash,subdomain,agent_protocol_version) VALUES($1,$2,'opnsense','fixture-only-hash','migration-device','fixture') RETURNING id`, tenant, actor).Scan(&device); err != nil {
		t.Fatal(err)
	}
	_, err = owner.ExecContext(ctx, `UPDATE devices SET platform='openwrt' WHERE id=$1`, device)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23514" || constraint.ConstraintName != "devices_platform_check" {
		t.Fatalf("previous schema did not enforce its platform constraint: %v", err)
	}
	if err := Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	var platform string
	var guiKey sql.NullString
	if err := owner.QueryRowContext(ctx, `SELECT platform,gui_public_key FROM devices WHERE id=$1`, device).Scan(&platform, &guiKey); err != nil || platform != "opnsense" || guiKey.Valid {
		t.Fatalf("migration changed the existing device: %v", err)
	}
	if _, err := owner.ExecContext(ctx, `UPDATE devices SET platform='openwrt' WHERE id=$1`, device); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `DELETE FROM devices WHERE id=$1`, device); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, actor); err != nil {
		t.Fatal(err)
	}
}
