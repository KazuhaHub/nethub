package store

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Remove only the disposable fixture's reserved role before forward migration;
// restoring it later must not silently grant worker functions to an old volume.
func legacyIssuerRoleFixture(t *testing.T, ctx context.Context, owner *sql.DB) func() {
	t.Helper()
	command := exec.CommandContext(ctx, "psql", "-X", "-qAt", "--host", "/var/run/postgresql", "--username", "postgres", "--dbname", "nethub", "--set", "ON_ERROR_STOP=1")
	command.Stdin = strings.NewReader("DROP OWNED BY nethub_issuer; DROP ROLE nethub_issuer;\n")
	if _, err := command.CombinedOutput(); err != nil {
		t.Fatal("could not prepare isolated legacy role fixture")
	}
	return func() {
		var absent bool
		if err := owner.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT FROM pg_roles WHERE rolname='nethub_issuer')`).Scan(&absent); err != nil || !absent {
			t.Error("migration silently created a host issuer role", err)
			return
		}
		command := exec.CommandContext(ctx, "/bin/sh", "/docker-entrypoint-initdb.d/00-nethub-roles.sh")
		command.Env = append(os.Environ(), "POSTGRES_USER=postgres")
		if _, err := command.CombinedOutput(); err != nil {
			t.Error("explicit fixture role bootstrap failed")
			return
		}
		var unexpected bool
		if err := owner.QueryRowContext(ctx, `SELECT has_function_privilege('nethub_issuer','public.claim_gui_certificate_job()','EXECUTE')`).Scan(&unexpected); err != nil || unexpected {
			t.Error("role bootstrap silently enabled existing worker functions", err)
			return
		}
		// This explicit fixture upgrade grants only the reviewed function boundary.
		if _, err := owner.ExecContext(ctx, `GRANT EXECUTE ON FUNCTION public.enqueue_gui_certificate_request(uuid),
 public.enqueue_due_gui_certificate_renewals(text,jsonb),
 public.read_current_relay_trust(text),public.publish_relay_trust(uuid,text,bytea,text,jsonb,timestamptz,timestamptz),
 public.claim_gui_certificate_job(),public.renew_gui_certificate_lease(uuid,uuid,bigint),
 public.release_gui_certificate_lease(uuid,uuid,bigint,text),
 public.read_gui_certificate_progress(uuid,uuid,bigint),
 public.save_gui_certificate_progress(uuid,uuid,bigint,text,jsonb),
 public.finish_gui_certificate_job(uuid,uuid,bigint,bytea,text,timestamptz,timestamptz,timestamptz,timestamptz) TO nethub_issuer`); err != nil {
			t.Error("explicit fixture function grant failed", err)
			return
		}
		t.Log("Legacy migration without issuer role preserved device API readiness; explicit role bootstrap and separate function grants were required")
	}
}
