package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrReadinessAuthority = errors.New("database runtime authority does not match the deployment boundary")

// CheckRuntimeRoles reads only PostgreSQL privilege metadata in one snapshot.
// It never exercises a forbidden write or reads device credentials to test access.
func CheckRuntimeRoles(ctx context.Context, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT current_user='nethub_web' AND session_user='nethub_web'
 AND (SELECT count(*)=2 FROM pg_roles r WHERE r.rolname IN ('nethub_web','nethub_authz')
   AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole
   AND NOT r.rolreplication AND NOT r.rolinherit AND NOT r.rolbypassrls
   AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid))
 AND NOT has_schema_privilege('nethub_web','public','CREATE')
 AND NOT has_schema_privilege('nethub_authz','public','CREATE')
 AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='public.devices'::regclass)
 AND NOT has_table_privilege('nethub_web','public.devices','INSERT,DELETE,TRUNCATE,TRIGGER,REFERENCES')
 AND NOT has_column_privilege('nethub_web','public.devices','device_secret_hash','SELECT')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='public.devices'::regclass
   AND a.attnum>0 AND NOT a.attisdropped
   AND (has_column_privilege('nethub_web',a.attrelid,a.attnum,'INSERT')
     OR (a.attname NOT IN ('label','revoked','revoked_at','revoked_by_user_id')
       AND has_column_privilege('nethub_web',a.attrelid,a.attnum,'UPDATE'))))
 AND NOT has_function_privilege('nethub_web','public.lookup_device_credential(uuid)','EXECUTE')
 AND NOT has_function_privilege('nethub_web','public.consume_enroll_token(bytea)','EXECUTE')
 AND NOT has_function_privilege('nethub_web','public.record_relay_traffic(jsonb,timestamp with time zone)','EXECUTE')`).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrReadinessAuthority
	}
	return tx.Commit()
}
