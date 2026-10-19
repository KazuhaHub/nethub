#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
stage=$(mktemp -d)
name="nethub-db-test-$(basename "$stage" | tr '[:upper:].' '[:lower:]-')"
image=${NETHUB_POSTGRES_TEST_IMAGE:-"$name:postgres"}
cleanup() {
    status=$?
    if [ "$status" -ne 0 ] && [ -f "$stage/build.log" ]; then tail -n 60 "$stage/build.log" >&2; fi
    docker rm -f -v "$name" >/dev/null 2>&1 || true
    if [ -z "${NETHUB_POSTGRES_TEST_IMAGE:-}" ]; then docker image rm "$image" >/dev/null 2>&1 || true; fi
    case "$stage" in /tmp/*|/var/tmp/*) rm -rf -- "$stage" ;; esac
}
trap cleanup EXIT HUP INT TERM
umask 077
mkdir "$stage/secrets"
for role in bootstrap nethub_owner nethub_web nethub_authz nethub_backup; do
    openssl rand -hex 32 > "$stage/secrets/pg_$role"
done
if [ -z "${NETHUB_POSTGRES_TEST_IMAGE:-}" ]; then
    docker build -f "$root/deploy/images/postgres/Dockerfile" -t "$image" "$root" > "$stage/build.log" 2>&1
fi
docker create --name "$name" --network none --entrypoint /bin/sh \
    -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD_FILE=/run/secrets/pg_bootstrap \
    -e POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 "$image" /tmp/start-postgres.sh >/dev/null
docker cp "$stage/secrets" "$name:/run/secrets"
docker cp "$root/deploy/postgres/00-nethub-roles.sh" "$name:/docker-entrypoint-initdb.d/00-nethub-roles.sh"
# docker cp retains host ownership; make only the test secret directory readable.
# Configure ownership before entrypoint drops privileges by wrapping that startup.
docker cp "$root/server/tests/start-postgres.sh" "$name:/tmp/start-postgres.sh"
docker start "$name" >/dev/null
ready=false
for attempt in $(seq 1 60); do
    if [ "$(docker inspect --format '{{.State.Running}}' "$name")" != true ]; then
        break
    fi
    if docker exec -u postgres "$name" pg_isready -h 127.0.0.1 -U postgres -d nethub >/dev/null 2>&1 &&
        docker exec -u postgres "$name" psql -X -d nethub -Atqc "SELECT count(*)=4 FROM pg_roles WHERE rolname IN ('nethub_owner','nethub_web','nethub_authz','nethub_backup')" 2>/dev/null | grep -qx t; then
        ready=true
        break
    fi
    sleep 1
done
if [ "$ready" != true ]; then
    echo 'PostgreSQL initialization did not become ready' >&2
    docker logs --tail 40 "$name" >&2
    exit 1
fi
if [ -n "${NETHUB_DATABASE_TEST_BINARY:-}" ]; then
    binary=$NETHUB_DATABASE_TEST_BINARY
else
    binary="$stage/database.test"
    (cd "$root/server" && CGO_ENABLED=0 GOOS=linux go test -c -o "$binary" ./internal/store)
fi
docker cp "$binary" "$name:/tmp/database.test"
if [ -n "${NETHUB_AUTHZ_TEST_BINARY:-}" ]; then
    authz_binary=$NETHUB_AUTHZ_TEST_BINARY
else
    authz_binary="$stage/nethub"
    (cd "$root/server" && CGO_ENABLED=0 GOOS=linux go build -o "$authz_binary" ./cmd/nethub)
fi
docker cp "$authz_binary" "$name:/tmp/nethub"
docker cp "$root/proto" "$name:/tmp/nethub-proto"
docker exec -u postgres -e NETHUB_DATABASE_TEST=1 -e NETHUB_PROTOCOL_FIXTURES=/tmp/nethub-proto -e NETHUB_AUTHZ_TEST_BINARY=/tmp/nethub "$name" /tmp/database.test -test.v -test.timeout=120s
# Re-execute the actual bootstrap hook and verify repeat initialization is safe.
docker exec -u postgres -e POSTGRES_USER=postgres "$name" sh /docker-entrypoint-initdb.d/00-nethub-roles.sh >/dev/null
