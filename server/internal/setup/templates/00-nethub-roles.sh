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
    -- The privileged host issuer enters this role explicitly over the local
    -- PostgreSQL socket. It has no login/password or inherited runtime authority.
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nethub_issuer') THEN
        CREATE ROLE nethub_issuer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOINHERIT NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nethub_issuer'
        AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
        AND NOT rolreplication AND NOT rolinherit AND NOT rolbypassrls)
       OR EXISTS (SELECT FROM pg_auth_members WHERE roleid='nethub_issuer'::regrole
                  OR member='nethub_issuer'::regrole) THEN
        RAISE EXCEPTION 'Issuer role flags or memberships need operator review';
    END IF;
END
$bootstrap$;
GRANT pg_read_all_data TO nethub_backup WITH INHERIT TRUE;
SELECT 'CREATE DATABASE nethub OWNER nethub_owner'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'nethub') \gexec
REVOKE ALL ON DATABASE nethub FROM PUBLIC;
GRANT CONNECT ON DATABASE nethub TO nethub_owner, nethub_web, nethub_authz, nethub_backup;
SQL

psql -X --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname nethub <<'SQL'
DO $issuer_privileges$
BEGIN
    IF EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f') AND
        (has_table_privilege('nethub_issuer',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
         OR has_any_column_privilege('nethub_issuer',c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
       OR EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind='S'
        AND has_sequence_privilege('nethub_issuer',c.oid,'USAGE,SELECT,UPDATE')) THEN
        RAISE EXCEPTION 'Issuer direct data privileges need operator review';
    END IF;
END
$issuer_privileges$;
GRANT USAGE ON SCHEMA public TO nethub_issuer;
SQL
