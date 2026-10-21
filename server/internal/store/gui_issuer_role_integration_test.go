package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func testGUIIssuerRole(t *testing.T, ctx context.Context, owner, web, authz *sql.DB) {
	var ready bool
	err := owner.QueryRowContext(ctx, `SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
 AND NOT rolcreaterole AND NOT rolreplication AND NOT rolinherit AND NOT rolbypassrls
 AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid=pg_roles.oid OR member=pg_roles.oid)
 AND has_schema_privilege(oid,'public','USAGE') AND NOT has_schema_privilege(oid,'public','CREATE')
 AND NOT has_table_privilege(oid,'public.devices','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
 AND NOT has_table_privilege(oid,'public.gui_certificate_requests','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
 AND NOT has_function_privilege(oid,'public.lookup_device_credential(uuid)','EXECUTE')
 AND NOT has_function_privilege(oid,'public.consume_enroll_token(bytea)','EXECUTE')
 FROM pg_roles WHERE rolname='nethub_issuer'`).Scan(&ready)
	if err != nil || !ready {
		t.Fatal("issuer role has unexpected login, membership or runtime authority", err)
	}
	for _, role := range []*sql.DB{owner, web, authz} {
		tx, err := role.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(ctx, `SET LOCAL ROLE nethub_issuer`)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			tx.Rollback()
			t.Fatal("application/migration login can assume issuer role", err)
		}
		tx.Rollback()
	}
	// The privileged host is already a trusted operation boundary. An ordinary
	// query in the explicitly selected SQL identity must still obey its grants.
	query := func(sql string) ([]byte, error) {
		command := exec.CommandContext(ctx, "psql", "-X", "-qAt", "--host", "/var/run/postgresql", "--username", "postgres", "--dbname", "nethub", "--set", "ON_ERROR_STOP=1", "--set", "VERBOSITY=sqlstate")
		command.Stdin = strings.NewReader("SET SESSION AUTHORIZATION nethub_issuer;\n" + sql + ";\n")
		return command.CombinedOutput()
	}
	output, err := query(`SELECT current_user,session_user`)
	if err != nil || strings.TrimSpace(string(output)) != "nethub_issuer|nethub_issuer" {
		t.Fatal("host did not select isolated SQL identity")
	}
	for _, sql := range []string{`SELECT count(*) FROM public.devices`, `SELECT count(*) FROM public.gui_certificate_requests`, `SELECT * FROM public.lookup_device_credential('00000000-0000-0000-0000-000000000000')`, `CREATE TABLE public.issuer_must_not_create(id integer)`} {
		output, err := query(sql)
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 || !strings.Contains(string(output), "42501") {
			t.Fatal("issuer direct SQL privilege boundary failed")
		}
	}
	if _, err := OpenRole(ctx, DatabaseConfig{}, "nethub_issuer"); err == nil {
		t.Fatal("no-login issuer was exposed as a password client role")
	}
	t.Run("bootstrap_preserves_unsafe_role_for_review", func(t *testing.T) {
		admin := func(statement string) {
			t.Helper()
			command := exec.CommandContext(ctx, "psql", "-X", "-qAt", "--host", "/var/run/postgresql", "--username", "postgres", "--dbname", "nethub", "--set", "ON_ERROR_STOP=1")
			command.Stdin = strings.NewReader(statement + ";\n")
			if _, err := command.CombinedOutput(); err != nil {
				t.Fatal("fixture administrator operation failed")
			}
		}
		bootstrap := func(wantFailure bool) {
			t.Helper()
			command := exec.CommandContext(ctx, "/bin/sh", "/docker-entrypoint-initdb.d/00-nethub-roles.sh")
			command.Env = append(os.Environ(), "POSTGRES_USER=postgres")
			output, err := command.CombinedOutput()
			if wantFailure {
				if err == nil || !strings.Contains(string(output), "need operator review") {
					t.Fatal("unsafe role did not stop bootstrap")
				}
			} else if err != nil {
				t.Fatal("restored fixture bootstrap failed")
			}
		}
		admin(`ALTER ROLE nethub_issuer LOGIN`)
		func() {
			defer admin(`ALTER ROLE nethub_issuer NOLOGIN`)
			bootstrap(true)
			var remains bool
			if err := owner.QueryRowContext(ctx, `SELECT rolcanlogin FROM pg_roles WHERE rolname='nethub_issuer'`).Scan(&remains); err != nil || !remains {
				t.Fatal("bootstrap silently repaired unsafe login flag", err)
			}
		}()
		admin(`GRANT nethub_issuer TO nethub_authz`)
		func() {
			defer admin(`REVOKE nethub_issuer FROM nethub_authz`)
			bootstrap(true)
			var remains bool
			if err := owner.QueryRowContext(ctx, `SELECT pg_has_role('nethub_authz','nethub_issuer','MEMBER')`).Scan(&remains); err != nil || !remains {
				t.Fatal("bootstrap silently repaired unexpected membership", err)
			}
		}()
		admin(`GRANT SELECT ON public.devices TO nethub_issuer`)
		func() {
			defer admin(`REVOKE SELECT ON public.devices FROM nethub_issuer`)
			bootstrap(true)
			var remains bool
			if err := owner.QueryRowContext(ctx, `SELECT has_table_privilege('nethub_issuer','public.devices','SELECT')`).Scan(&remains); err != nil || !remains {
				t.Fatal("bootstrap silently repaired unexpected data grant", err)
			}
		}()
		for _, permission := range []struct{ grant, revoke, probe string }{
			{`GRANT CREATE ON SCHEMA public TO nethub_issuer`, `REVOKE CREATE ON SCHEMA public FROM nethub_issuer`,
				`SELECT has_schema_privilege('nethub_issuer','public','CREATE')`},
			{`GRANT EXECUTE ON FUNCTION public.lookup_device_credential(uuid) TO nethub_issuer`,
				`REVOKE EXECUTE ON FUNCTION public.lookup_device_credential(uuid) FROM nethub_issuer`,
				`SELECT has_function_privilege('nethub_issuer','public.lookup_device_credential(uuid)','EXECUTE')`},
			{`GRANT EXECUTE ON FUNCTION public.consume_enroll_token(bytea) TO nethub_issuer`,
				`REVOKE EXECUTE ON FUNCTION public.consume_enroll_token(bytea) FROM nethub_issuer`,
				`SELECT has_function_privilege('nethub_issuer','public.consume_enroll_token(bytea)','EXECUTE')`},
		} {
			admin(permission.grant)
			func() {
				defer admin(permission.revoke)
				bootstrap(true)
				var remains bool
				if err := owner.QueryRowContext(ctx, permission.probe).Scan(&remains); err != nil || !remains {
					t.Fatal("bootstrap silently repaired unexpected schema or credential-function privilege", err)
				}
			}()
		}
		bootstrap(false)
	})
	t.Log("No-login issuer identity, zero inherited/data/credential authority, application role refusal and actual restricted SQL queries passed")
}
