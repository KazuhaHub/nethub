#!/bin/sh
set -eu
chown -R postgres:postgres /run/secrets
chmod 0700 /run/secrets
chmod 0600 /run/secrets/pg_*
exec /usr/local/bin/docker-entrypoint.sh postgres
