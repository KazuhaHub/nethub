package store

import (
	"context"
	"database/sql"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func testBackupIdentity(t *testing.T, ctx context.Context, backup, web *sql.DB) {
	t.Helper()
	before, err := BackupDeploymentFingerprint(ctx, backup)
	if err != nil || len(before) != 64 {
		t.Fatalf("initial backup identity: %v", err)
	}
	if _, err := BackupDeploymentFingerprint(ctx, web); !errors.Is(err, ErrReadinessAuthority) {
		t.Fatalf("non-backup login accepted: %v", err)
	}
	admin := func(ctx context.Context, query string) error {
		command := exec.CommandContext(ctx, "psql", "-X", "-qAt", "--host", "/var/run/postgresql", "--username", "postgres", "--dbname", "nethub", "--set", "ON_ERROR_STOP=1")
		command.Stdin = strings.NewReader(query + ";\n")
		return command.Run()
	}
	for _, tc := range []struct{ name, change, restore string }{
		{"missing_bypass", "ALTER ROLE nethub_backup NOBYPASSRLS", "ALTER ROLE nethub_backup BYPASSRLS"},
		{"superuser", "ALTER ROLE nethub_backup SUPERUSER", "ALTER ROLE nethub_backup NOSUPERUSER"},
		{"extra_membership", "GRANT nethub_owner TO nethub_backup", "REVOKE nethub_owner FROM nethub_backup"},
		{"table_write", "GRANT UPDATE ON devices TO nethub_backup", "REVOKE UPDATE ON devices FROM nethub_backup"},
		{"column_write", "GRANT UPDATE(label) ON devices TO nethub_backup", "REVOKE UPDATE(label) ON devices FROM nethub_backup"},
		{"schema_create", "GRANT CREATE ON SCHEMA public TO nethub_backup", "REVOKE CREATE ON SCHEMA public FROM nethub_backup"},
		{"database_create", "GRANT CREATE ON DATABASE nethub TO nethub_backup", "REVOKE CREATE ON DATABASE nethub FROM nethub_backup"},
		{"foreign_schema_write", "CREATE SCHEMA pgxtemp_probe; CREATE TABLE pgxtemp_probe.probe(id integer); GRANT USAGE ON SCHEMA pgxtemp_probe TO nethub_backup; GRANT UPDATE ON pgxtemp_probe.probe TO nethub_backup", "DROP SCHEMA IF EXISTS pgxtemp_probe CASCADE"},
		{"definer_function", "GRANT EXECUTE ON FUNCTION lookup_device_credential(uuid) TO nethub_backup", "REVOKE EXECUTE ON FUNCTION lookup_device_credential(uuid) FROM nethub_backup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := admin(ctx, tc.change); err != nil {
				t.Fatal("owned role perturbation failed")
			}
			t.Cleanup(func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := admin(cleanupCtx, tc.restore); err != nil {
					t.Error("owned backup role cleanup failed")
				}
			})
			if _, err := BackupDeploymentFingerprint(ctx, backup); !errors.Is(err, ErrReadinessAuthority) {
				t.Fatalf("unsafe backup role accepted: %v", err)
			}
			if err := admin(ctx, tc.restore); err != nil {
				t.Fatal("backup role restore failed")
			}
			after, err := BackupDeploymentFingerprint(ctx, backup)
			if err != nil || after != before {
				t.Fatalf("retained deployment identity changed: %v", err)
			}
		})
	}
	t.Log("Read-only backup metadata rejected elevated roles, extra memberships, schema/table/column writes and credential functions; restoring privileges retained the deployment identity")
}
