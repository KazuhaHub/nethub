package store

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type DatabaseConfig struct {
	Host, Database, PasswordFile, SSLMode string
	Port                                  uint16
}

// OpenRole reads the password from a service-specific file, never from argv.
func OpenRole(ctx context.Context, config DatabaseConfig, role string) (*sql.DB, error) {
	switch role {
	case "nethub_owner", "nethub_web", "nethub_authz", "nethub_backup":
	default:
		return nil, errors.New("unsupported database role")
	}
	if config.Host == "" || config.Port == 0 || config.Database == "" || config.PasswordFile == "" {
		return nil, errors.New("database host, port, name, and password file are required")
	}
	if config.SSLMode != "verify-full" && config.SSLMode != "disable" {
		return nil, errors.New("database TLS mode must be verify-full or explicitly disabled for an isolated local network")
	}
	file, err := os.Open(config.PasswordFile)
	if err != nil {
		return nil, errors.New("database password file is unavailable")
	}
	defer file.Close()
	password, err := io.ReadAll(io.LimitReader(file, 4097))
	secret := strings.TrimSpace(string(password))
	if err != nil || len(password) > 4096 || len(secret) < 32 || strings.ContainsAny(secret, "\r\n\x00") {
		return nil, errors.New("database password file is invalid")
	}
	u := url.URL{Scheme: "postgres", User: url.User(role), Host: net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port))), Path: config.Database}
	query := url.Values{"sslmode": {config.SSLMode}}
	u.RawQuery = query.Encode()
	connection, err := pgx.ParseConfig(u.String())
	if err != nil {
		return nil, errors.New("database connection settings are invalid")
	}
	connection.Password = secret
	db := stdlib.OpenDB(*connection)
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(2)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, errors.New("database connection failed")
	}
	return db, nil
}
