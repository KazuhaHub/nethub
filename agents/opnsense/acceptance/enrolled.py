"""Exercise the installed plugin against the owned six-service Compose fixture."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import uuid

from guest import GuestError, invoke


ROOT = Path(__file__).resolve().parents[3]


def private_json(path, value):
    path.write_text(json.dumps(value), encoding='utf-8')
    path.chmod(0o600)


def exercise(guest, stage, port, project, evidence):
    stage = Path(stage).resolve(strict=True)
    if (os.geteuid() != 0 or not re.fullmatch(r'nethub-stack-test-[a-z0-9-]+', project)
            or not 1 <= port <= 65535 or stage.parent not in (Path('/tmp'), Path('/var/tmp'))):
        raise GuestError('Owned native deployment fixture required')
    work = stage / 'relay-test'
    compose = ['docker', 'compose', '-p', project,
               '-f', str(stage / 'deployment/docker-compose.yml'),
               '-f', str(stage / 'deployment/docker-compose.override.yml'), '-f', str(stage / 'test.yml')]
    ids = invoke(compose + ['ps', '-q'], 'owned native deployment inventory').decode().splitlines()
    if len(ids) != 6 or any(not re.fullmatch(r'[a-f0-9]{64}', value) for value in ids):
        raise GuestError('Exactly six running deployment services required')
    for identifier in ids:
        value = json.loads(invoke(['docker', 'inspect', identifier], 'owned native service identity'))[0]
        if value['Config']['Labels'].get('com.docker.compose.project') != project:
            raise GuestError('Deployment service ownership changed')
    base = ['curl', '--silent', '--show-error', '--noproxy', '*', '--max-time', '10',
            '--cacert', str(stage / 'console-ca.pem'), '--connect-to',
            f'console.example.com:443:127.0.0.1:{port}']

    def request(path, body=None, *, secret=None, expected=200):
        arguments = list(base)
        if secret is None:
            arguments += ['-b', str(work / 'cookies'), '-H', '@' + str(work / 'csrf-header')]
        else:
            header = work / 'native-auth-header'
            header.write_text('Authorization: Bearer ' + secret + '\n', encoding='ascii')
            header.chmod(0o600)
            arguments += ['-H', '@' + str(header)]
        if body is not None:
            payload = work / 'native-request.json'
            private_json(payload, body)
            arguments += ['-H', 'Content-Type: application/json', '-H', 'Origin: https://console.example.com',
                          '--data-binary', '@' + str(payload)]
        response = invoke(arguments + ['--write-out', '\n%{http_code}',
                                      'https://console.example.com' + path], 'native verified console API', timeout=12)
        raw, _, status = response.rpartition(b'\n')
        if status != str(expected).encode():
            raise GuestError('Native console API outcome differed')
        return json.loads(raw)

    nonce = uuid.uuid4().hex
    marker = work / 'native-fixture-nonce'
    marker.write_text(nonce + '\n', encoding='ascii')
    marker.chmod(0o600)
    guest.put(marker, marker.name)
    guest.put(Path(__file__).with_name('native-fixture.php'), 'native-fixture.php')
    guest.ssh('chmod 0600 /root/nethub-ci/native-fixture-nonce\n', 'private native fixture identity')

    def fixture(action, **values):
        path = work / 'native-fixture-input.json'
        private_json(path, dict(action=action, nonce=nonce, **values))
        guest.put(path, path.name)
        raw = guest.ssh('/usr/local/bin/php /root/nethub-ci/native-fixture.php '
                        '< /root/nethub-ci/native-fixture-input.json\n', 'native fixture ' + action)
        value = json.loads(raw)
        if value.get('success') is not True or not isinstance(value.get('result'), dict):
            raise GuestError('Native fixture preparation was not confirmed')
        return value['result']

    ca = (stage / 'console-ca.pem').read_text(encoding='ascii')
    if fixture('trust', ca_pem=ca) != {'trusted': True}:
        raise GuestError('Native console system trust unavailable')
    guest.ssh("printf '\\n10.0.2.2 console.example.com\\n' >> /etc/hosts\n"
              "/usr/local/bin/python3.13 - <<'PY'\n"
              "import socket,ssl,urllib.request\n"
              "assert socket.gethostbyname('console.example.com')=='10.0.2.2'\n"
              f"with urllib.request.urlopen('https://console.example.com:{port}/',timeout=10) as r: assert r.status==200\n"
              "PY\n", 'guest verified console trust and egress')

    token = request('/api/v1/console/enroll-tokens', {}, expected=201)['token']
    private_json(work / 'native-enrollment-token.json', {'token': token})
    config = work / 'native-browser-private.json'
    browser = Path(__file__).with_name('enrolled-browser.mjs')

    def page_action(action):
        private_json(config, {'origin': f'https://127.0.0.1:{guest.gui_port}',
                             'console': f'https://console.example.com:{port}', 'token': token,
                             'action': action, 'evidence': str(evidence)})
        invoke([os.environ['NETHUB_NODE_BINARY'], str(browser), str(config)],
               'installed native ' + action + ' page', timeout=120)

    def native_read(name):
        raw = guest.ssh("cd /usr/local/opnsense/scripts/nethub-agent\n"
                        "/usr/local/bin/python3.13 - <<'PY'\n"
                        "import json\nfrom rotation_backend import NativeRotationBackend\n"
                        "print(json.dumps(NativeRotationBackend().read()))\nPY\n", 'native model readback')
        value = json.loads(raw)
        private_json(work / name, value)
        return value

    page_action('enroll')
    guest.ssh('/usr/local/sbin/configctl nethub-agent trust\n', 'native trust preflight')
    before = native_read('native-before.json')
    if (before['enabled'] != '1' or not re.fullmatch(r'[a-z0-9]{8}', before['subdomain'])
            or str(uuid.UUID(before['device_id'])) != before['device_id']):
        raise GuestError('Native enrollment identity differed')
    host = before['subdomain'] + '.router.example.com'
    identity = fixture('csr', host=host)
    csr, key, cert, authority = [work / name for name in
                               ('native-gui.csr', 'native-fixture-ca.key', 'native-gui.crt', 'native-fixture-ca.crt')]
    csr.write_text(identity['csr_pem'], encoding='ascii')
    invoke(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=NetHub isolated GUI fixture', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-keyout', str(key), '-out', str(authority)], 'owned GUI fixture authority')
    key.chmod(0o600)
    extensions = work / 'native-gui.ext'
    extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n'
                          'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:' + host + '\n', encoding='ascii')
    invoke(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(authority), '-CAkey', str(key),
            '-CAcreateserial', '-days', '1', '-sha256', '-extfile', str(extensions), '-out', str(cert)],
           'public native CSR fixture signing')
    installed = fixture('install', host=host, ca_pem=authority.read_text(encoding='ascii'),
                        certificate_pem=cert.read_text(encoding='ascii'))
    if not installed['installed'] or installed['key_sha256'] != identity['key_sha256']:
        raise GuestError('Native GUI key was replaced')
    guest.ssh('/usr/local/etc/rc.restart_webgui\n', 'owned native GUI reload', timeout=30)
    request('/api/v1/console/devices/' + before['device_id'] + '/open', {})
    database = invoke(compose + ['ps', '-q', 'postgres'], 'native database identity').decode().strip()

    def sql(query, role='postgres'):
        if role not in ('postgres', 'nethub_web'):
            raise GuestError('Unexpected native proof database role')
        return invoke(['docker', 'exec', '-i', database, 'psql', '-X', '-U', role, '-d', 'nethub',
                       '-v', 'ON_ERROR_STOP=1', '-Atc', query], 'native rotation SQL proof').decode().strip()

    # Match the same explicit local fixture source used by the existing relay test.
    caddy = invoke(compose + ['ps', '-q', 'caddy'], 'native fixture edge identity').decode().strip()
    networks = json.loads(invoke(['docker', 'inspect', caddy], 'native fixture edge network'))[0]['NetworkSettings']['Networks']
    if len(networks) != 1:
        raise GuestError('Ambiguous native fixture edge')
    gateway = str(ipaddress.ip_address(next(iter(networks.values()))['Gateway']))
    with socket.socket() as listener, socket.socket() as client:
        listener.settimeout(2)
        client.settimeout(2)
        listener.bind((gateway, 0))
        listener.listen(1)
        client.bind((gateway, 0))
        client.connect(listener.getsockname())
        connection, peer = listener.accept()
        connection.close()
    local_source = str(ipaddress.ip_address(peer[0]))
    interfaces = json.loads(invoke(['ip', '-j', 'addr'], 'owned native fixture source addresses'))
    owned = {item['local'] for interface in interfaces for item in interface['addr_info']}
    if local_source not in owned:
        raise GuestError('Native fixture peer is not host owned')
    if local_source != gateway:
        actor = str(uuid.UUID(json.loads((stage / 'login-response.json').read_text())['user']['id']))
        tenant = str(uuid.UUID(sql("SELECT tenant_id FROM devices WHERE id='" + before['device_id'] + "';")))
        sql("BEGIN; SELECT set_config('app.tenant_id','" + tenant + "',true); "
            "SELECT append_audit('user','" + actor + "','device.access_granted','" + before['device_id'] +
            "',jsonb_build_object('source_ip','" + local_source + "','expires_at',opened.expires_at,'fixture_local_nat',true)) "
            "FROM (SELECT open_device('" + actor + "','" + before['device_id'] + "','" + local_source +
            "'::inet) AS expires_at) opened; COMMIT;", role='nethub_web')

    def route():
        r = subprocess.run(['curl', '--silent', '--show-error', '--fail', '--noproxy', '*', '--max-time', '3',
                            '--interface', gateway, '--cacert', str(authority), '--connect-to', host + ':8443:' + gateway + ':8443',
                            '--write-out', '\n%{http_code}', 'https://' + host + ':8443/'], capture_output=True, timeout=5)
        raw, _, status = r.stdout.rpartition(b'\n')
        return r.returncode == 0 and status == b'200' and b'usernamefld' in raw

    for _ in range(30):
        if route():
            break
        time.sleep(1)
    else:
        raise GuestError('Installed native assigned route did not pass verified TLS')
    device = before['device_id']
    stable_query = "SELECT jsonb_build_array(id,tenant_id,owner_user_id,subdomain,gui_public_key,enrolled_at)::text FROM devices WHERE id='" + device + "';"
    stable = sql(stable_query)
    grants_query = "SELECT source_ip::text||expires_at::text FROM device_access_grants WHERE device_id='" + device + "' ORDER BY source_ip;"
    grants = sql(grants_query)
    started = time.monotonic()
    page_action('rotate')
    after = native_read('native-after.json')
    changed = {'device_secret', 'domain_claim'}
    if (any(after[key] == before[key] for key in changed)
            or any(after[key] != before[key] for key in before if key not in changed)):
        raise GuestError('Native rotation did not preserve its assignment and policy')
    if sql(stable_query) != stable or sql(grants_query) != grants:
        raise GuestError('Native rotation changed identity or source grants')
    for _ in range(30):
        if route():
            break
        time.sleep(1)
    else:
        raise GuestError('Rotated native assigned route did not recover verified TLS')
    elapsed = round((time.monotonic() - started) * 1000)
    checked = fixture('inspect', host=host)
    if checked != {'key_sha256': identity['key_sha256'], 'security_checks_enabled': True, 'alternate_present': True}:
        raise GuestError('Native rotation changed GUI identity or security policy')
    relay_ca = work / 'native-relay-ca.pem'
    relay_ca.write_bytes(base64.b64decode(before['relay_ca'], validate=True))
    stale_config = work / 'native-old-claim.json'
    private_json(stale_config, {'serverAddr': '127.0.0.1', 'serverPort': int(before['server_port']),
        'loginFailExit': True, 'auth': {'method': 'token', 'token': before['frp_token']},
        'log': {'to': 'console', 'level': 'warn'},
        'metadatas': {'device_id': device, 'domain_claim': before['domain_claim']},
        'transport': {'heartbeatInterval': 10, 'heartbeatTimeout': 30,
                      'tls': {'enable': True, 'serverName': before['server_name'], 'trustedCaFile': str(relay_ca)}},
        'proxies': [{'name': 'nethub-' + device + '-web', 'type': 'https', 'localIP': '127.0.0.1',
                     'localPort': 1, 'subdomain': before['subdomain']}]})
    authz = invoke(compose + ['ps', '-q', 'nethub-authz'], 'native authorization service identity').decode().strip()

    def hook_events():
        raw = invoke(['docker', 'logs', authz], 'native hook admission evidence')
        if len(raw) > 8 * 1024**2:
            raise GuestError('Native hook evidence exceeds bound')
        events = []
        for line in raw.splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and value.get('msg') == 'Relay hook decision':
                events.append(value)
        return events

    # The existing heartbeat snapshot publishes claim floors every five seconds.
    # This new Login probe must fail on authorization rather than on TLS/setup.
    time.sleep(6)
    count = len(hook_events())
    with (work / 'native-old-claim.log').open('xb') as log:
        stale = subprocess.Popen([str(stage / 'official/frpc'), '-c', str(stale_config)], stdout=log, stderr=log)
        try:
            if stale.wait(timeout=10) == 0:
                raise GuestError('Old native claim unexpectedly established control')
        except subprocess.TimeoutExpired:
            raise GuestError('Old native claim did not promptly fail Login') from None
        finally:
            if stale.poll() is None:
                stale.terminate()
                try:
                    stale.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    stale.kill()
                    stale.wait(timeout=5)
    events = hook_events()[count:]
    if (not any(event.get('operation') == 'Login' and event.get('decision') == 'device_denied' for event in events)
            or any(event.get('operation') == 'Login' and event.get('decision') == 'allowed' for event in events)):
        raise GuestError('Old native claim refusal was not bound to real Login admission')
    request('/api/v1/devices/rotate', {'agent_protocol_version': '1.6.0', 'device_id': device,
            'operation_id': str(uuid.uuid4()), 'replacement_secret': before['device_secret'],
            'expected_relay_ca_sha256': hashlib.sha256(base64.b64decode(before['relay_ca'], validate=True)).hexdigest()},
            secret=before['device_secret'], expected=401)
    result = {'passed': True, 'actual_native_page_enrollment_and_rotation': True,
              'native_model_readback_verified': True, 'same_route_verified_TLS_before_and_after': True,
              'old_credential_HTTP_401': True, 'identity_and_source_grants_retained': True,
              'old_native_claim_actual_official_frpc_Login_denied': True,
              'native_GUI_key_retained': True, 'GUI_security_checks_and_exact_alias_retained': True,
              'rotation_to_verified_route_ms': elapsed,
              'interrupted_native_recovery_or_other_device_acceptance': False,
              'public_network_or_formal_release_acceptance': False, 'full_goal_complete': False}
    private_json(evidence / 'installed-rotation.json', result)
    return result
