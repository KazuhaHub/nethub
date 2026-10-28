package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"
)

// BackupDeploymentFingerprint checks the read-only backup login and binds archives
// to the retained single-tenant database identity, independently of rotating keys.
func BackupDeploymentFingerprint(ctx context.Context, db *sql.DB) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT current_user='nethub_backup' AND session_user='nethub_backup'
 AND EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname='nethub_backup'
   AND r.rolcanlogin AND r.rolbypassrls AND NOT r.rolsuper AND NOT r.rolcreatedb
   AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolinherit)
 AND (SELECT count(*)=1 AND bool_and(m.roleid='pg_read_all_data'::regrole
   AND m.inherit_option AND NOT m.admin_option) FROM pg_auth_members m
   WHERE m.member='nethub_backup'::regrole)
 AND NOT has_schema_privilege('nethub_backup','public','CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE CASE WHEN n.nspname='public' AND c.relkind IN ('r','p','v','m','f') THEN
     has_table_privilege('nethub_backup',c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
     OR has_any_column_privilege('nethub_backup',c.oid,'INSERT,UPDATE,REFERENCES') ELSE false END)
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE CASE WHEN n.nspname='public' AND c.relkind='S' THEN
     has_sequence_privilege('nethub_backup',c.oid,'USAGE,UPDATE') ELSE false END)
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname='public' AND p.prosecdef
     AND has_function_privilege('nethub_backup',p.oid,'EXECUTE'))`).Scan(&valid)
	if err != nil {
		return "", err
	}
	if !valid {
		return "", ErrReadinessAuthority
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text FROM tenants ORDER BY id LIMIT 2`)
	if err != nil {
		return "", err
	}
	var identity string
	count := 0
	for rows.Next() {
		if err := rows.Scan(&identity); err != nil {
			rows.Close()
			return "", err
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	if count != 1 {
		return "", ErrReadinessAuthority
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte("nethub-database-backup-v1\x00" + identity))
	return hex.EncodeToString(digest[:]), nil
}
