#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" != 0 ]; then
    echo 'Run this isolated Compose acceptance test as root for secret UID checks' >&2
    exit 2
fi
python3 - <<'PY'
import socket,subprocess
engine=subprocess.check_output(['docker','version','--format','{{.Server.Version}}'],text=True,timeout=15).strip()
assert int(engine.split('.')[0])>=28, 'Loopback callback isolation requires Docker Engine 28 or newer'
for address,port in (('0.0.0.0',7000),('0.0.0.0',8443),('127.0.0.1',9000)):
    with socket.socket() as listener:
        try:
            listener.bind((address,port))
        except OSError:
            raise SystemExit('Relay acceptance requires unused TCP 7000/8443 and loopback 9000; no existing service was changed')
PY
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
python3 "$root/server/tests/test_compose_boundaries.py"
python3 "$root/server/tests/test_trust_report_fault.py"
stage=$(mktemp -d)
project="nethub-stack-test-$(basename "$stage" | tr '[:upper:].' '[:lower:]-')"
image=${NETHUB_RUNTIME_TEST_IMAGE:-"nethub-stack-test:$(basename "$stage" | tr '[:upper:].' '[:lower:]-')"}
postgres_image=${NETHUB_POSTGRES_TEST_IMAGE:-"$image-postgres"}
caddy_image=${NETHUB_CADDY_TEST_IMAGE:-"$image-caddy"}
frps_image=${NETHUB_FRPS_TEST_IMAGE:-"$image-frps"}
backup_image=${NETHUB_BACKUP_TEST_IMAGE:-"$image-backup"}
frps_container="$project-frps-smoke"
provider_key_container="$project-provider-key-smoke"
http01_test_image="$project-http01-test:local"
http01_binary_holder="$project-http01-binary"
guiacme_test_image="$project-guiacme-test:local"
guiacme_binary_holder="$project-guiacme-binary"
guiissuer_test_image="$project-guiissuer-test:local"
guiissuer_binary_holder="$project-guiissuer-binary"
setup_test_image="$project-setup-test:local"
setup_binary_holder="$project-setup-binary"
pebble_image='ghcr.io/letsencrypt/pebble@sha256:5080492187bea12909c053d7a2b90a9e95104ef1c82381828e7823db71ce7e54'
compose_for() (
    limit=$1
    shift
    exec timeout --signal=TERM --kill-after=5 "$limit" docker compose -p "$project" \
        -f "$stage/deployment/docker-compose.yml" -f "$stage/deployment/docker-compose.override.yml" \
        -f "$stage/test.yml" "$@"
)
compose() { compose_for 210 "$@"; }
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$status" -ne 0 ]; then
        echo 'Compose acceptance failed; retained service states follow' >&2
        timeout --kill-after=5 15 docker ps -a --filter "label=com.docker.compose.project=$project" \
            --format '{{.Label "com.docker.compose.service"}} state={{.State}} status={{.Status}}' >&2 || true
        for log in "$stage/build.log" "$stage/postgres-build.log" "$stage/caddy-build.log" "$stage/frps-build.log" "$stage/backup-build.log" "$stage/http01-build.log" "$stage/guiacme-build.log" "$stage/guiissuer-build.log" "$stage/setup-build.log"; do
            if [ -f "$log" ]; then tail -n 60 "$log" >&2; fi
        done
    fi
    for container in "$frps_container" "$provider_key_container" "$http01_binary_holder" "$guiacme_binary_holder" "$guiissuer_binary_holder" "$setup_binary_holder"; do
        timeout --kill-after=5 15 docker rm -f "$container" >/dev/null 2>&1 || true
    done
    for test_image in "$http01_test_image" "$guiacme_test_image" "$guiissuer_test_image" "$setup_test_image"; do
        timeout --kill-after=5 15 docker image rm "$test_image" >/dev/null 2>&1 || true
    done
    if [ -f "$stage/test.yml" ]; then
        compose_for 20 logs --no-color > "$stage/runtime-final.log" 2>&1 || true
        compose_for 40 down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    if [ -z "${NETHUB_RUNTIME_TEST_IMAGE:-}" ]; then timeout --kill-after=5 15 docker image rm "$image" >/dev/null 2>&1 || true; fi
    if [ -z "${NETHUB_POSTGRES_TEST_IMAGE:-}" ]; then timeout --kill-after=5 15 docker image rm "$postgres_image" >/dev/null 2>&1 || true; fi
    if [ -z "${NETHUB_CADDY_TEST_IMAGE:-}" ]; then timeout --kill-after=5 15 docker image rm "$caddy_image" >/dev/null 2>&1 || true; fi
    if [ -z "${NETHUB_FRPS_TEST_IMAGE:-}" ]; then timeout --kill-after=5 15 docker image rm "$frps_image" >/dev/null 2>&1 || true; fi
    if [ -z "${NETHUB_BACKUP_TEST_IMAGE:-}" ]; then timeout --kill-after=5 15 docker image rm "$backup_image" >/dev/null 2>&1 || true; fi
    if [ -n "${NETHUB_COMPOSE_EVIDENCE:-}" ]; then
        mkdir -p "$NETHUB_COMPOSE_EVIDENCE"
        tar -czf "$NETHUB_COMPOSE_EVIDENCE/compose-private-evidence.tar.gz" -C "$stage" .
    fi
    case "$stage" in /tmp/*|/var/tmp/*) rm -rf -- "$stage" ;; esac
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -z "${NETHUB_RUNTIME_TEST_IMAGE:-}" ]; then
    docker build -f "$root/deploy/Dockerfile" -t "$image" "$root" > "$stage/build.log" 2>&1
fi
if [ -z "${NETHUB_POSTGRES_TEST_IMAGE:-}" ]; then
    docker build -f "$root/deploy/images/postgres/Dockerfile" -t "$postgres_image" "$root" > "$stage/postgres-build.log" 2>&1
fi
if [ -z "${NETHUB_CADDY_TEST_IMAGE:-}" ]; then
    docker build -f "$root/deploy/images/caddy/Dockerfile" -t "$caddy_image" "$root" > "$stage/caddy-build.log" 2>&1
fi
if [ -z "${NETHUB_FRPS_TEST_IMAGE:-}" ]; then
    docker build -f "$root/deploy/images/frps/Dockerfile" -t "$frps_image" "$root" > "$stage/frps-build.log" 2>&1
fi
if [ -z "${NETHUB_BACKUP_TEST_IMAGE:-}" ]; then
    docker build --target backup -f "$root/deploy/Dockerfile" -t "$backup_image" "$root" > "$stage/backup-build.log" 2>&1
fi
docker build --target http01-acceptance -f "$root/deploy/Dockerfile" -t "$http01_test_image" "$root" > "$stage/http01-build.log" 2>&1
docker create --name "$http01_binary_holder" --network none "$http01_test_image" /http01.test >/dev/null
docker cp "$http01_binary_holder:/http01.test" "$stage/http01.test"
docker cp "$http01_binary_holder:/nethub" "$stage/http01-nethub"
docker rm "$http01_binary_holder" >/dev/null
chmod 0700 "$stage/http01.test" "$stage/http01-nethub"
NETHUB_HTTP01_CADDY_IMAGE="$caddy_image" NETHUB_HTTP01_TEST_BINARY="$stage/http01-nethub" \
    "$stage/http01.test" -test.v -test.run '^Test(CaddyPublicHTTP01Route|NativeHTTP01CleanupCLI)$' -test.timeout=120s
python3 "$root/server/tests/http01-cleanup.py" "$root" "$stage/http01-nethub" \
    "$stage/http01.test" "$stage/http01-cleanup"
docker pull --platform linux/amd64 "$pebble_image" > "$stage/pebble-pull.log" 2>&1
docker build --target guiacme-acceptance -f "$root/deploy/Dockerfile" -t "$guiacme_test_image" "$root" > "$stage/guiacme-build.log" 2>&1
docker create --name "$guiacme_binary_holder" --network none "$guiacme_test_image" /guiacme.test >/dev/null
docker cp "$guiacme_binary_holder:/guiacme.test" "$stage/guiacme.test"
docker rm "$guiacme_binary_holder" >/dev/null
chmod 0700 "$stage/guiacme.test"
NETHUB_GUIACME_PEBBLE_IMAGE="$pebble_image" NETHUB_GUIACME_CADDY_IMAGE="$caddy_image" "$stage/guiacme.test" -test.v -test.run '^TestPebble(OrderAdmission|HTTP01Validation|CertificateIssuance|CoordinatorRecovery)$' -test.timeout=180s
python3 "$root/server/tests/test_gui_issuer_host.py"
python3 "$root/server/tests/gui-issuer-host.py" "$root" "$stage/http01-nethub" \
    "$stage/guiacme.test" "$stage/gui-issuer-host" "$postgres_image" "$caddy_image" "$pebble_image"
docker build --target guiissuer-acceptance -f "$root/deploy/Dockerfile" -t "$guiissuer_test_image" "$root" > "$stage/guiissuer-build.log" 2>&1
docker create --name "$guiissuer_binary_holder" --network none "$guiissuer_test_image" /guiissuer.test >/dev/null
docker cp "$guiissuer_binary_holder:/guiissuer.test" "$stage/guiissuer.test"
docker rm "$guiissuer_binary_holder" >/dev/null
chmod 0700 "$stage/guiissuer.test"
docker build --target setup-acceptance -f "$root/deploy/Dockerfile" -t "$setup_test_image" "$root" > "$stage/setup-build.log" 2>&1
docker create --name "$setup_binary_holder" --network none "$setup_test_image" /setup.test >/dev/null
docker cp "$setup_binary_holder:/setup.test" "$stage/setup.test"
docker rm "$setup_binary_holder" >/dev/null
chmod 0700 "$stage/setup.test"
if [ "${NETHUB_SCAN_IMAGES:-0}" = 1 ]; then
    mkdir "$stage/scans"
    scan_image() {
        docker image save -o "$stage/scans/image.tar" "$2"
        if ! docker run --rm -v "$stage/scans:/scan" \
            aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222 \
            image --input /scan/image.tar --cache-dir /scan/cache --scanners vuln \
            --severity HIGH,CRITICAL --exit-code 1 --format json --output "/scan/$1.json" > "$stage/scans/$1.log" 2>&1; then
            cat "$stage/scans/$1.log" >&2
            python3 - "$stage/scans/$1.json" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
if p.exists():
    for result in json.loads(p.read_text()).get('Results',[]):
        for item in result.get('Vulnerabilities',[]):
            print(item['VulnerabilityID'],item['PkgName'],item['InstalledVersion'],item.get('FixedVersion','unfixed'),item['Severity'],file=sys.stderr)
PY
            return 1
        fi
        rm "$stage/scans/image.tar"
    }
    scan_image runtime "$image"
    scan_image postgres "$postgres_image"
    scan_image caddy "$caddy_image"
    scan_image frps "$frps_image"
    scan_image backup "$backup_image"
    echo 'All five assembled deployment images passed HIGH/CRITICAL vulnerability checks'
fi
python3 "$root/server/tests/frps-smoke.py" "$stage" "$frps_image" "$frps_container"
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
python3 - "$root/deploy/Caddyfile" "$stage/Caddyfile" <<'PY'
import pathlib,sys
source=pathlib.Path(sys.argv[1]).read_text()
assert source.count('{$NETHUB_CONSOLE_HOST} {')==1
pathlib.Path(sys.argv[2]).write_text(source.replace('{$NETHUB_CONSOLE_HOST} {','https://console.example.com {\n    tls internal',1))
PY
chmod 0644 "$stage/Caddyfile"
cat > "$stage/test.yml" <<YAML
services:
  postgres:
    image: $postgres_image
    labels:
      org.nethub.gui-issuer-test: $project
  migrate:
    image: $image
  backup:
    image: $backup_image
  nethub-web:
    image: $image
  nethub-authz:
    image: $image
  frps:
    image: $frps_image
  admin-bootstrap:
    image: $image
  caddy:
    image: $caddy_image
    ports: !override ["127.0.0.1:$port:443"]
    volumes:
      - $stage/Caddyfile:/etc/caddy/Caddyfile:ro
YAML
compose --profile bootstrap config --format json > "$stage/compose.json"
python3 - "$stage" <<'PY'
import json,pathlib,sys
s=pathlib.Path(sys.argv[1]);cfg=json.loads((s/'compose.json').read_text());services=cfg['services']
assert set(services)=={'postgres','migrate','backup','nethub-web','nethub-authz','frps','caddy','admin-bootstrap'}
assert {name for name,service in services.items() if service.get('ports')}=={'caddy','nethub-authz'}
hook_ports=services['nethub-authz']['ports']
assert len(hook_ports)==1
assert hook_ports[0]['host_ip']=='127.0.0.1' and str(hook_ports[0]['published'])=='9000'
assert hook_ports[0]['target']==9000 and hook_ports[0]['protocol']=='tcp'
assert services['nethub-web']['depends_on']['migrate']['condition']=='service_completed_successfully'
assert services['nethub-authz']['depends_on']['migrate']['condition']=='service_completed_successfully'
backup=services['backup']
assert backup['depends_on']['migrate']['condition']=='service_completed_successfully'
assert set(backup['networks'])=={'database'} and not backup.get('ports')
assert backup['command']==['backup','serve','--sslmode','disable']
assert len(backup['volumes'])==2
assert any(v['target']=='/run/secrets' and v['source'].endswith('/secrets/backup') and v['read_only'] for v in backup['volumes'])
assert any(v['target']=='/var/lib/nethub-backups' and v['type']=='volume' for v in backup['volumes'])
assert len(backup['tmpfs'])==1 and backup['tmpfs'][0].startswith('/run/nethub-backup:')
assert {'noexec','nosuid','nodev','uid=65532','gid=65532'}<=set(backup['tmpfs'][0].split(':',1)[1].split(','))
assert services['frps']['network_mode']=='host' and not services['frps'].get('ports')
assert services['frps']['depends_on']['nethub-authz']['condition']=='service_healthy'
web=services['nethub-web'];assert len(web['volumes'])==1 and web['volumes'][0]['source'].endswith('/secrets/web')
assert web['command'].count('--secrets-key-file')==1
assert web['command'][web['command'].index('--secrets-key-file')+1]=='/run/secrets/secrets_key'
assert services['admin-bootstrap']['volumes'][0]['source'].endswith('/secrets/migrate')
assert services['nethub-web']['networks']['edge']['ipv4_address']!=services['caddy']['networks']['edge']['ipv4_address']
manifest=json.loads((s/'deployment/setup.json').read_text());assert manifest['confirmed_at']
assert manifest['version']==3 and len(manifest['files'])==22
assert all(item['uid']==70 for item in manifest['files'] if item['path'].startswith('secrets/postgres/'))
for item in manifest['files']:
    path=s/'deployment'/item['path'];assert path.stat().st_uid==item['uid'] and path.stat().st_mode&0o777==0o600
for service in ('nethub-web','nethub-authz','frps'):
    assert all('/issuer' not in volume['source'] and not volume['source'].endswith('/secrets') for volume in services[service]['volumes'])
for name in ('runtime/relay/relay-cert.pem','runtime/relay/relay-key.pem','runtime/trust/relay-ca.pem'):
    path=s/'deployment'/name;assert path.stat().st_uid==65532 and path.stat().st_mode&0o777==0o600
PY
python3 "$root/deploy/frp/fetch.py" "$stage/official/frps"
docker run --rm --network none --entrypoint /frps-official \
    -v "$stage/official/frps:/frps-official:ro" \
    -v "$stage/deployment/secrets/frps:/run/secrets:ro" \
    -v "$stage/deployment/runtime/relay:/run/relay:ro" \
    "$frps_image" verify -c /run/secrets/frps.toml > "$stage/frps-official-verify.log" 2>&1
echo 'Official checksum-verified frps accepted the generated production configuration'
echo 'Starting the isolated Compose services (210-second command deadline, 150-second health wait)'
compose up -d --wait --wait-timeout 150 > "$stage/start.log" 2>&1
for key_case in missing malformed unsafe; do
    printf '%s\n' 'invalid-provider-key-fixture' > "$stage/provider-key-fixture"
    chmod 600 "$stage/provider-key-fixture"
    chown 65532 "$stage/provider-key-fixture"
    key_path=/run/provider-key-fixture
    if [ "$key_case" = missing ]; then key_path=/run/missing-provider-key; fi
    if [ "$key_case" = unsafe ]; then
        openssl rand -hex 32 > "$stage/provider-key-fixture"
        chmod 644 "$stage/provider-key-fixture"
    fi
    key_status=0
    timeout --signal=TERM --kill-after=5 30 docker run --rm --name "$provider_key_container" \
        --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
        -v "$stage/provider-key-fixture:/run/provider-key-fixture:ro" "$image" web \
        --password-file /run/unused-database-password --origin https://console.example.com \
        --device-domain router.example.com --secrets-key-file "$key_path" \
        > "$stage/provider-key-$key_case.log" 2>&1 || key_status=$?
    if [ "$key_status" -ne 1 ] || ! grep -Fqx 'Console provider-encryption key is missing or invalid' "$stage/provider-key-$key_case.log"; then
        echo "Console provider-key refusal failed for $key_case (exit $key_status)" >&2
        exit 1
    fi
done
chmod 600 "$stage/provider-key-fixture"
echo 'Actual web container loaded its generated provider key and refused missing, malformed and unsafe keys without database or network access'
echo 'Isolated Compose startup completed; creating the initial administrator (90-second deadline)'
openssl rand -hex 24 > "$stage/admin-password"
compose_for 90 run --rm -T admin-bootstrap --email compose-admin@example.com --password-stdin < "$stage/admin-password" > "$stage/admin.log" 2>&1
echo 'Initial administrator created; verifying that repeat initialization is closed'
repeat_status=0
compose_for 90 run --rm -T admin-bootstrap --email second@example.com --password-stdin < "$stage/admin-password" > "$stage/repeat-admin.log" 2>&1 || repeat_status=$?
if [ "$repeat_status" -ne 1 ] || ! grep -Fqx 'Accounts already exist; initial administrator creation is closed' "$stage/repeat-admin.log"; then
    echo "Repeated administrator bootstrap did not return the expected account-state refusal (exit $repeat_status)" >&2
    exit 1
fi
echo 'Repeated administrator bootstrap returned the expected account-state refusal'
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
code=$(curl -sS --insecure --noproxy '*' --connect-to "console.example.com:443:127.0.0.1:$port" -o /dev/null -w '%{http_code}' -X POST https://console.example.com/api/v1/frp/hooks)
[ "$code" = 404 ]
if [ "${NETHUB_BROWSER_TEST:-0}" = 1 ]; then
    "${NETHUB_NODE_BINARY:-node}" "$root/server/web/tests/deployment.mjs" \
        "$port" "$stage/admin-password" "$stage/browser" "$(compose ps -q postgres)" "$(compose ps -q nethub-web)"
    if [ -n "${NETHUB_BROWSER_EVIDENCE:-}" ]; then
        mkdir -p "$NETHUB_BROWSER_EVIDENCE"
        for name in login.png empty-inventory.png enrollment-masked.png mobile.png results.json; do
            cp "$stage/browser/$name" "$NETHUB_BROWSER_EVIDENCE/$name"
            chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$NETHUB_BROWSER_EVIDENCE/$name"
        done
        chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$NETHUB_BROWSER_EVIDENCE"
    fi
fi
compose logs --no-color > "$stage/runtime.log"
python3 - "$stage" <<'PY'
import json,pathlib,sys
s=pathlib.Path(sys.argv[1]);assert json.loads((s/'devices.json').read_text())=={'items':[],'next_cursor':None};token=json.loads((s/'token.json').read_text());assert len(token['token'])==43
log=(s/'runtime.log').read_text();assert token['token'] not in log and (s/'admin-password').read_text().strip() not in log
assert '<script' in (s/'index.html').read_text()
print('Compose first-start, isolated secret mounts, admin login, empty inventory, token issuance, health isolation, and log checks passed')
PY
python3 "$root/agents/opnsense/plugin/frp_artifact.py" --platform linux_amd64 --binary frpc --output "$stage/official/frpc"
docker cp "$(compose ps -q caddy):/data/caddy/pki/authorities/local/root.crt" "$stage/console-ca.pem" >/dev/null
python3 "$root/server/tests/relay-deployment.py" "$stage" "$port" "$project"
compose logs --no-color > "$stage/relay-runtime.log"
python3 - "$stage" <<'PY'
import json,pathlib,sys
s=pathlib.Path(sys.argv[1]);log=(s/'relay-runtime.log').read_text()
log+='\n'+'\n'.join(path.read_text() for path in (s/'relay-test').glob('*.log'))
def credentials(value):
    if isinstance(value,dict):
        for key,item in value.items():
            if key in ('device_secret','frp_token','domain_claim','enroll_token','token') and isinstance(item,str):
                assert len(item)>=32
                yield item
            else:yield from credentials(item)
    elif isinstance(value,list):
        for item in value:yield from credentials(item)
for path in (s/'relay-test').glob('*.json'):
    for value in credentials(json.loads(path.read_text())):assert value not in log
for path in (s/'deployment/secrets').rglob('*'):
    if path.is_file() and path.stat().st_size==65:assert path.read_text().strip() not in log
print('Enrolled credentials, claims and deployment secrets are absent from runtime logs')
print('Nested client auth tokens and original/tampered claims are absent from client and captured authz/frps logs')
PY
# Exercise the privileged host adapter against the live disposable database.
# Missing fixture identity must fail here rather than silently skip the test.
database_id=$(compose ps -q postgres)
[ -n "$database_id" ]
database_image_id=$(docker image inspect --format '{{.Id}}' "$postgres_image")
NETHUB_TEST_GUI_SQL_CONTAINER="$database_id" NETHUB_TEST_GUI_SQL_IMAGE="$database_image_id" \
NETHUB_TEST_GUI_SQL_PROJECT="$project" NETHUB_TEST_AUTHORITY_DIRECTORY="$stage/deployment" \
NETHUB_TEST_AUTHORITY_CLI="$stage/http01-nethub" \
NETHUB_TEST_AUTHORITY_COMPOSE="$stage/test.yml" "$stage/guiissuer.test" -test.v \
    -test.run '^TestNative(DockerSQLRunner|RelayAuthorityService|RelayAuthorityTransition)$' -test.timeout=300s
NETHUB_TEST_GUI_SQL_PROJECT="$project" NETHUB_TEST_AUTHORITY_DIRECTORY="$stage/deployment" \
NETHUB_TEST_AUTHORITY_COMPOSE="$stage/test.yml" NETHUB_TEST_AUTHORITY_CLI="$stage/http01-nethub" \
NETHUB_TEST_HTTP01_CLI_REQUIRED=1 "$stage/setup.test" -test.v \
    -test.run '^(TestNativeAuthorityProcessRecovery|TestAuthorityCommand.*|TestHTTP01Initialization.*)$' -test.timeout=720s
# The administrative fixture creates a separate tenant. Run it only after the
# single-tenant bootstrap/browser/relay acceptance and before final teardown.
database_id=$(compose ps -q postgres)
[ -n "$database_id" ] || { echo "Required GUI issuer database fixture is missing" >&2; exit 1; }
database_image_id=$(docker image inspect --format '{{.Id}}' "$postgres_image")
NETHUB_GUIACME_PEBBLE_IMAGE="$pebble_image" NETHUB_GUIACME_CADDY_IMAGE="$caddy_image" \
NETHUB_TEST_GUI_SQL_CONTAINER="$database_id" NETHUB_TEST_GUI_SQL_IMAGE="$database_image_id" \
NETHUB_TEST_GUI_SQL_PROJECT="$project" "$stage/guiacme.test" -test.v \
    -test.run '^TestPebbleCoordinatorDatabaseRecovery$' -test.timeout=120s
compose down -v --remove-orphans > "$stage/down.log" 2>&1
python3 "$root/server/tests/external-proxy.py" "$stage" "$root" "$image" "$postgres_image" "$caddy_image" "$frps_image"
cat > "$stage/failure.yml" <<'YAML'
services:
  migrate:
    command: [version, unexpected]
YAML
if docker compose -p "$project" -f "$stage/deployment/docker-compose.yml" -f "$stage/deployment/docker-compose.override.yml" -f "$stage/test.yml" -f "$stage/failure.yml" up -d > "$stage/migration-failure.log" 2>&1; then
    echo 'Stack unexpectedly started despite failed migration' >&2
    exit 1
fi
migration=$(compose ps -aq migrate)
[ -n "$migration" ]
[ "$(docker inspect --format '{{.State.ExitCode}}' "$migration")" = 2 ]
running=$(compose ps --status running --services)
if printf '%s\n' "$running" | grep -qx nethub-web; then echo 'Web started after failed migration' >&2; exit 1; fi
if printf '%s\n' "$running" | grep -Eq '^(nethub-authz|frps)$'; then echo 'Relay started after failed migration' >&2; exit 1; fi
if printf '%s\n' "$running" | grep -qx backup; then echo 'Backup started after failed migration' >&2; exit 1; fi
echo 'Failed migration prevented console startup'
if [ -n "${NETHUB_IMAGE_EVIDENCE:-}" ]; then
    mkdir -p "$NETHUB_IMAGE_EVIDENCE"
    docker image save -o "$NETHUB_IMAGE_EVIDENCE/images.tar" "$image" "$postgres_image" "$caddy_image" "$frps_image" "$backup_image"
    gzip -1 "$NETHUB_IMAGE_EVIDENCE/images.tar"
    (cd "$NETHUB_IMAGE_EVIDENCE" && sha256sum images.tar.gz > SHA256SUMS)
    python3 - "$NETHUB_IMAGE_EVIDENCE" "$image" "$postgres_image" "$caddy_image" "$frps_image" "$backup_image" <<'PY'
import hashlib,json,pathlib,subprocess,sys,tarfile
output=pathlib.Path(sys.argv[1]);images={}
with tarfile.open(output/'images.tar.gz') as archive:
    manifest=json.load(archive.extractfile('manifest.json'))
    for service,tag in zip(('runtime','postgres','caddy','frps','backup'),sys.argv[2:]):
        entry=next(item for item in manifest if tag in item['RepoTags'])
        config_file=archive.getmember(entry['Config']);assert config_file.isfile() and config_file.size<=1048576
        raw=archive.extractfile(config_file).read();config=json.loads(raw)
        info=json.loads(subprocess.check_output(['docker','image','inspect',tag],text=True))[0]
        assert info['RootFS']['Layers']==config['rootfs']['diff_ids']
        assert info['Os']==config['os'] and info['Architecture']==config['architecture']
        images[service]={'tag':tag,'id':info['Id'],'config_digest':'sha256:'+hashlib.sha256(raw).hexdigest(),
                         'platform':config['os']+'/'+config['architecture'],'diff_ids':config['rootfs']['diff_ids']}
(output/'images.json').write_text(json.dumps(images,indent=2))
PY
    chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$NETHUB_IMAGE_EVIDENCE" \
        "$NETHUB_IMAGE_EVIDENCE/images.tar.gz" "$NETHUB_IMAGE_EVIDENCE/SHA256SUMS" "$NETHUB_IMAGE_EVIDENCE/images.json"
    echo 'Saved only tested immutable images and checksums; runtime credentials are excluded'
fi
