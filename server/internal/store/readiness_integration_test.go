package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func testReadinessRoles(t *testing.T, ctx context.Context, owner, web, authz *sql.DB) {
	t.Helper()
	admin := func(ctx context.Context, query string) error {
		command := exec.CommandContext(ctx, "psql", "-X", "-qAt", "--host", "/var/run/postgresql", "--username", "postgres", "--dbname", "nethub", "--set", "ON_ERROR_STOP=1")
		command.Stdin = strings.NewReader(query + ";\n")
		_, err := command.CombinedOutput()
		return err
	}
	compiled := func(t *testing.T, wantSuccess bool) {
		t.Helper()
		binary := os.Getenv("NETHUB_AUTHZ_TEST_BINARY")
		if binary == "" {
			t.Fatal("compiled doctor is required for runtime-role acceptance")
		}
		command := exec.CommandContext(ctx, binary, "doctor", "--database-roles", "--host", "127.0.0.1", "--password-file", "/run/secrets/pg_nethub_web", "--sslmode", "disable")
		output, err := command.CombinedOutput()
		if (err == nil) != wantSuccess {
			t.Fatal("compiled role doctor returned an unexpected result")
		}
		text := string(output)
		if wantSuccess && !strings.Contains(text, "read-only metadata snapshot") {
			t.Fatal("compiled doctor omitted its metadata scope")
		}
		if !wantSuccess && !strings.Contains(text, "review runtime role flags and memberships") {
			t.Fatal("compiled doctor omitted remediation")
		}
	}
	if err := CheckRuntimeRoles(ctx, web); err != nil {
		t.Fatal("reviewed Web identity did not pass read-only readiness", err)
	}
	compiled(t, true)
	for _, db := range []*sql.DB{owner, authz} {
		if err := CheckRuntimeRoles(ctx, db); !errors.Is(err, ErrReadinessAuthority) {
			t.Fatal("non-Web connection passed Web readiness", err)
		}
	}
	for _, test := range []struct{ name, grant, restore string }{
		{"identity_update", `GRANT UPDATE(device_secret_hash) ON devices TO nethub_web`, `REVOKE UPDATE(device_secret_hash) ON devices FROM nethub_web`},
		{"credential_read", `GRANT SELECT(device_secret_hash) ON devices TO nethub_web`, `REVOKE SELECT(device_secret_hash) ON devices FROM nethub_web`},
		{"credential_function", `GRANT EXECUTE ON FUNCTION lookup_device_credential(uuid) TO nethub_web`, `REVOKE EXECUTE ON FUNCTION lookup_device_credential(uuid) FROM nethub_web`},
		{"runtime_bypass", `ALTER ROLE nethub_web BYPASSRLS`, `ALTER ROLE nethub_web NOBYPASSRLS`},
		{"authz_membership", `GRANT nethub_backup TO nethub_authz`, `REVOKE nethub_backup FROM nethub_authz`},
		{"device_RLS", `ALTER TABLE devices NO FORCE ROW LEVEL SECURITY`, `ALTER TABLE devices FORCE ROW LEVEL SECURITY`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := admin(ctx, test.grant); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := admin(clean, test.restore); err != nil {
					t.Error("readiness fixture authority restoration failed", err)
				}
			})
			if err := CheckRuntimeRoles(ctx, web); !errors.Is(err, ErrReadinessAuthority) {
				t.Fatal("unexpected authority passed readiness", err)
			}
			if test.name == "identity_update" {
				compiled(t, false)
			}
		})
		if err := CheckRuntimeRoles(ctx, web); err != nil {
			t.Fatal("restored runtime boundary did not recover", err)
		}
	}
	compiled(t, true)
	t.Log("Read-only doctor metadata and compiled CLI rejected Web identity writes, credential reads/functions, runtime bypass, authz memberships and missing forced RLS without changing device rows")
}
