#!/bin/sh
set -eu

# PostgreSQL reads the mounted files itself; passwords never enter argv or SQL.
psql -X --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
SET log_statement = 'none';
SET log_min_error_statement = 'panic';
DO $bootstrap$
DECLARE
    role_name text;
    secret text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['nethub_owner', 'nethub_web', 'nethub_authz', 'nethub_backup'] LOOP
        secret := btrim(pg_read_file('/run/secrets/pg_' || role_name), E' \r\n');
        IF secret !~ '^[a-f0-9]{64}$' THEN
            RAISE EXCEPTION 'Role password file must contain 32 random bytes encoded as lowercase hex';
        END IF;
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('CREATE ROLE %I', role_name);
        END IF;
        EXECUTE format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT %s PASSWORD %L',
            role_name, CASE WHEN role_name IN ('nethub_owner', 'nethub_backup') THEN 'BYPASSRLS' ELSE 'NOBYPASSRLS' END, secret);
    END LOOP;
END
$bootstrap$;
GRANT pg_read_all_data TO nethub_backup WITH INHERIT TRUE;
SELECT 'CREATE DATABASE nethub OWNER nethub_owner'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'nethub') \gexec
REVOKE ALL ON DATABASE nethub FROM PUBLIC;
GRANT CONNECT ON DATABASE nethub TO nethub_owner, nethub_web, nethub_authz, nethub_backup;
SQL
