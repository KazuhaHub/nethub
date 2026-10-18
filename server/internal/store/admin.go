package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

var ErrAlreadyInitialized = errors.New("initial administrator creation is closed because accounts already exist")

// CreateInitialAdmin is a local, one-shot owner operation, never an HTTP route.
// Locking users excludes concurrent bootstrap and ordinary account mutations
// until the new account, local-admin counter, and audit entry commit together.
func CreateInitialAdmin(ctx context.Context, db *sql.DB, email, password string) error {
	email, err := auth.NormalizeEmail(email)
	if err != nil {
		return errors.New("a valid administrator email is required")
	}
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 15 || len(password) > auth.MaxPasswordBytes || strings.ContainsAny(password, "\r\n\x00") {
		return errors.New("administrator password must contain at least 15 characters and at most 1024 UTF-8 bytes")
	}
	var role string
	var superuser, bypass bool
	if err = db.QueryRowContext(ctx, `SELECT current_user,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&role, &superuser, &bypass); err != nil {
		return errors.New("administrator role verification failed")
	}
	if role != "nethub_owner" || superuser || !bypass {
		return errors.New("initial administrator creation requires the isolated nethub_owner role")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return errors.New("administrator password hashing failed")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM tenants ORDER BY id LIMIT 2 FOR UPDATE`)
	if err != nil {
		return err
	}
	var tenant string
	count := 0
	for rows.Next() {
		if err = rows.Scan(&tenant); err != nil {
			rows.Close()
			return err
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("administrator bootstrap requires exactly one migrated tenant")
	}
	var populated bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM users)`).Scan(&populated); err != nil {
		return err
	}
	if populated {
		return ErrAlreadyInitialized
	}
	if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
		return err
	}
	var actor string
	if err = tx.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,$2,'admin',$3) RETURNING id`, tenant, email, hash).Scan(&actor); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `SELECT append_audit('user',$1,'admin.bootstrap',NULL,'{"source":"local_cli"}'::jsonb)`, actor); err != nil {
		return err
	}
	return tx.Commit()
}
