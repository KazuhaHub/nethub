package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"io/fs"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func Migrate(ctx context.Context, db *sql.DB) error {
	var role string
	var superuser, bypass bool
	if err := db.QueryRowContext(ctx, `SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&role, &superuser, &bypass); err != nil {
		return err
	}
	if role != "nethub_owner" || superuser || !bypass {
		return errors.New("migration requires the isolated nethub_owner role")
	}
	files, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files, goose.WithSessionLocker(locker))
	if err != nil {
		return err
	}
	_, err = provider.Up(ctx)
	return err
}
