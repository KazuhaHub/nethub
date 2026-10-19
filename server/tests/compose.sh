#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" != 0 ]; then
    echo 'Run this isolated Compose acceptance test as root for secret UID checks' >&2
    exit 2
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
stage=$(mktemp -d)
project="nethub-stack-test-$(basename "$stage" | tr '[:upper:].' '[:lower:]-')"
image="nethub-stack-test:$(basename "$stage" | tr '[:upper:].' '[:lower:]-')"
compose() { docker compose -p "$project" -f "$stage/deployment/docker-compose.yml" -f "$stage/deployment/docker-compose.override.yml" -f "$stage/test.yml" "$@"; }
cleanup() {
    if [ -f "$stage/test.yml" ]; then
        compose logs --no-color > "$stage/runtime-final.log" 2>&1 || true
        compose down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    docker image rm "$image" >/dev/null 2>&1 || true
    if [ -n "${NETHUB_COMPOSE_EVIDENCE:-}" ]; then
        mkdir -p "$NETHUB_COMPOSE_EVIDENCE"
        tar -czf "$NETHUB_COMPOSE_EVIDENCE/compose-private-evidence.tar.gz" -C "$stage" .
    fi
    case "$stage" in /tmp/*|/var/tmp/*) rm -rf -- "$stage" ;; esac
}
trap cleanup EXIT HUP INT TERM

docker build -f "$root/deploy/Dockerfile" -t "$image" "$root" > "$stage/build.log" 2>&1
printf '%s\n' 'I HAVE VERIFIED THE NETHUB SECRET BACKUP' | docker run --rm -i --network none --user 0 \
    -v "$root:$root:ro" -v "$stage:$stage" "$image" init --offline \
    --source-directory "$root" --directory "$stage/deployment" --backup-directory "$stage/backup" \
    --console-host console.example.com --device-domain router.example.com > "$stage/init.log" 2>&1
docker run --rm --network none --user 0 -v "$stage:$stage:ro" "$image" doctor --directory "$stage/deployment" > "$stage/doctor.log"

port=$(python3 - <<'PY'
import socket
with socket.socket() as listener:
    listener.bind(('127.0.0.1',0))
    print(listener.getsockname()[1])
PY
)
cat > "$stage/Caddyfile" <<'CADDY'
https://console.example.com {
    tls internal
    @internal path /healthz /healthz/*
    respond @internal 404
    reverse_proxy nethub-web:8080
}
CADDY
chmod 0644 "$stage/Caddyfile"
cat > "$stage/test.yml" <<YAML
services:
  migrate:
    image: $image
  nethub-web:
    image: $image
  admin-bootstrap:
    image: $image
  caddy:
    ports: !override ["127.0.0.1:$port:443"]
    volumes:
      - $stage/Caddyfile:/etc/caddy/Caddyfile:ro
YAML
compose --profile bootstrap config --format json > "$stage/compose.json"
python3 - "$stage" <<'PY'
import json,pathlib,sys
s=pathlib.Path(sys.argv[1]);cfg=json.loads((s/'compose.json').read_text());services=cfg['services']
assert set(services)=={'postgres','migrate','nethub-web','caddy','admin-bootstrap'}
assert [name for name,service in services.items() if service.get('ports')]==['caddy']
assert services['nethub-web']['depends_on']['migrate']['condition']=='service_completed_successfully'
web=services['nethub-web'];assert len(web['volumes'])==1 and web['volumes'][0]['source'].endswith('/secrets/web')
assert services['admin-bootstrap']['volumes'][0]['source'].endswith('/secrets/migrate')
assert services['nethub-web']['networks']['edge']['ipv4_address']!=services['caddy']['networks']['edge']['ipv4_address']
manifest=json.loads((s/'deployment/setup.json').read_text());assert manifest['confirmed_at']
for item in manifest['files']:
    path=s/'deployment'/item['path'];assert path.stat().st_uid==item['uid'] and path.stat().st_mode&0o777==0o600
PY
compose up -d --wait --wait-timeout 150 > "$stage/start.log" 2>&1
openssl rand -hex 24 > "$stage/admin-password"
compose run --rm -T admin-bootstrap --email compose-admin@example.com --password-stdin < "$stage/admin-password" > "$stage/admin.log" 2>&1
if compose run --rm -T admin-bootstrap --email second@example.com --password-stdin < "$stage/admin-password" > "$stage/repeat-admin.log" 2>&1; then
    echo 'Repeated administrator bootstrap unexpectedly succeeded' >&2
    exit 1
fi
python3 - "$stage" <<'PY'
import json,pathlib,sys
s=pathlib.Path(sys.argv[1]);(s/'login.json').write_text(json.dumps({'email':'compose-admin@example.com','password':(s/'admin-password').read_text().rstrip('\n')}))
PY
request() { curl -fsS --insecure --noproxy '*' --connect-to "console.example.com:443:127.0.0.1:$port" "$@"; }
request https://console.example.com/ > "$stage/index.html"
request -c "$stage/cookies" -H 'Content-Type: application/json' -H 'Origin: https://console.example.com' --data-binary "@$stage/login.json" https://console.example.com/api/v1/console/login > "$stage/login-response.json"
python3 - "$stage" <<'PY'
import json,pathlib,sys
s=pathlib.Path(sys.argv[1]);data=json.loads((s/'login-response.json').read_text());assert data['user']['role']=='admin';(s/'csrf-header').write_text('X-CSRF-Token: '+data['csrf_token']+'\n')
PY
request -b "$stage/cookies" https://console.example.com/api/v1/console/devices > "$stage/devices.json"
request -b "$stage/cookies" -H "@$stage/csrf-header" -H 'Content-Type: application/json' -H 'Origin: https://console.example.com' --data '{}' https://console.example.com/api/v1/console/enroll-tokens > "$stage/token.json"
code=$(curl -sS --insecure --noproxy '*' --connect-to "console.example.com:443:127.0.0.1:$port" -o /dev/null -w '%{http_code}' https://console.example.com/healthz)
[ "$code" = 404 ]
compose logs --no-color > "$stage/runtime.log"
python3 - "$stage" <<'PY'
import json,pathlib,sys
s=pathlib.Path(sys.argv[1]);assert json.loads((s/'devices.json').read_text())=={'items':[],'next_cursor':None};token=json.loads((s/'token.json').read_text());assert len(token['token'])==43
log=(s/'runtime.log').read_text();assert token['token'] not in log and (s/'admin-password').read_text().strip() not in log
assert '<script' in (s/'index.html').read_text()
print('Compose first-start, isolated secret mounts, admin login, empty inventory, token issuance, health isolation, and log checks passed')
PY
compose down -v --remove-orphans > "$stage/down.log" 2>&1
cat > "$stage/failure.yml" <<'YAML'
services:
  migrate:
    command: [version, unexpected]
YAML
if docker compose -p "$project" -f "$stage/deployment/docker-compose.yml" -f "$stage/deployment/docker-compose.override.yml" -f "$stage/test.yml" -f "$stage/failure.yml" up -d > "$stage/migration-failure.log" 2>&1; then
    echo 'Stack unexpectedly started despite failed migration' >&2
    exit 1
fi
running=$(compose ps --status running --services)
if printf '%s\n' "$running" | grep -qx nethub-web; then echo 'Web started after failed migration' >&2; exit 1; fi
echo 'Failed migration prevented console startup'
