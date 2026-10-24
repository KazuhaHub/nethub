"""Exercise device-side response validation, secret handoff and verified HTTPS."""
import base64
import copy
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'agents/opnsense/plugin/src/usr/local/opnsense/scripts/nethub-agent'
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('nethub_enrollment', SCRIPTS / 'enrollment.py')
ENROLL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENROLL)
SAMPLE = json.loads((ROOT / 'proto/examples/valid/enroll-response.json').read_text())
PHP = ROOT / 'agents/opnsense/plugin/src/usr/local/opnsense/mvc/app/models/OPNsense/NetHubAgent/Enrollment.php'


def test_real_response_fixture_and_optional_extensions():
    sample = copy.deepcopy(SAMPLE)
    sample.update(agent_protocol_version='1.2.3-preview.1+build', future_optional={'ignored': True})
    result = ENROLL.validate_response(sample)
    assert result['device_id'] == sample['device_id']
    assert 'future_optional' not in result
    assert sample['future_optional'] == {'ignored': True}


@pytest.mark.parametrize('change', [
    {'device_id': '../device'}, {'device_secret': 'A' * 42 + 'B'}, {'frp_token': 'f' * 65},
    {'server_addr': 'host.example.com\nvalue=true'}, {'server_addr': 'fe80::1%iface'},
    {'server_port': True}, {'server_port': 0}, {'server_port': '7000'}, {'server_port': 65536},
    {'server_name': 'host.example.com/path'}, {'subdomain': '-bad'}, {'subdomain': 'a' * 64},
    {'agent_protocol_version': '01.0.0'}, {'agent_protocol_version': '1.0.0-01'},
    {'relay_ca_pem': 'private-input-must-not-appear'}, {'domain_claim': 'private-input-must-not-appear'},
])
def test_response_fields_are_validated_without_echo(change):
    sample = copy.deepcopy(SAMPLE)
    sample.update(change)
    with pytest.raises(ENROLL.ProtocolError, match='^Invalid enrollment response$'):
        ENROLL.validate_response(sample)


def test_incompatible_protocol_and_claim_identity():
    sample = copy.deepcopy(SAMPLE)
    sample['agent_protocol_version'] = '2.0.0'
    with pytest.raises(ENROLL.ProtocolError, match='^Incompatible agent protocol; supported major is 1$'):
        ENROLL.validate_response(sample)
    for field, replacement in [('device_id', '22222222-2222-4222-8222-222222222222'),
                               ('subdomain', 'another'), ('key_id', 'BAD'),
                               ('issued_at', '2026-02-31T00:00:00.000000Z')]:
        sample = copy.deepcopy(SAMPLE)
        payload, signature = sample['domain_claim'].split('.')
        value = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        value[field] = replacement
        sample['domain_claim'] = base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=') + '.' + signature
        with pytest.raises(ENROLL.ProtocolError, match='^Invalid enrollment response$'):
            ENROLL.validate_response(sample)


@pytest.mark.parametrize('body', [b'{"token":"first","token":"second"}', b'[]', b'{} trailing',
                                 b'{"extension":NaN}', b'{"x":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}',
                                 b'x' * 65537, b'\xff'],
                         ids=['duplicate', 'array', 'trailer', 'nan', 'depth', 'size', 'utf8'])
def test_ambiguous_and_unbounded_json_is_rejected(body):
    with pytest.raises(ENROLL.ProtocolError, match='^Invalid enrollment response$'):
        ENROLL.decode_json(body)


@pytest.mark.parametrize('origin', [
    'http://console.example.com', 'https://user:secret@console.example.com', 'https://console.example.com?token=x',
    'https://console.example.com#fragment', 'https://console.example.com/api', 'https://console.example.com:0',
    'https://console.example.com:65536', 'https://console.example.com\n', 'https://console.example.com\\path',
    'https://[fe80::1%eth0]', 'https://console.example.com:', 'https://console.example.com//',
])
def test_console_origin_cannot_change_token_destination(origin):
    with pytest.raises(ENROLL.ProtocolError, match='^Invalid console HTTPS address$'):
        ENROLL.validate_origin(origin)


@pytest.mark.parametrize('origin,expected', [
    ('https://console.example.com/', 'https://console.example.com'),
    ('https://Console.Example.com:8443', 'https://console.example.com:8443'),
    ('https://127.0.0.1:8443', 'https://127.0.0.1:8443'),
    ('https://[::1]:8443', 'https://[::1]:8443'),
])
def test_operator_selected_private_origins_are_allowed(origin, expected):
    assert ENROLL.validate_origin(origin) == expected


def test_ca_bundle_is_current_and_bounded():
    ca = SAMPLE['relay_ca_pem']
    assert ENROLL.validate_ca(ca) == ca
    for value in [ca + ca, ca + '\n', ca + 'unexpected', ca.replace('CERTIFICATE', 'PRIVATE KEY')]:
        with pytest.raises(ENROLL.ProtocolError):
            ENROLL.validate_ca(value)
    for instant in [0, 4102444800]:
        with pytest.raises(ENROLL.ProtocolError):
            ENROLL.validate_ca(ca, now=instant)


@pytest.mark.skipif(not hasattr(os, 'O_NOFOLLOW'), reason='Requires the appliance POSIX file boundary')
def test_private_request_is_consumed_once_and_validated_before_use(tmp_path):
    directory = tmp_path / 'requests'
    directory.mkdir(mode=0o700)
    path = directory / ('enroll-' + 'a' * 32 + '.json')
    path.write_text(json.dumps({'origin': 'https://console.example.com', 'token': 'A' * 43}))
    path.chmod(0o600)
    assert ENROLL.consume_request(path, directory)['token'] == 'A' * 43
    assert not path.exists()
    with pytest.raises(ENROLL.ProtocolError, match='^Invalid private enrollment request$'):
        ENROLL.consume_request(path, directory)
    path.write_text('{"token":"A","token":"B"}')
    path.chmod(0o600)
    with pytest.raises(ENROLL.ProtocolError):
        ENROLL.consume_request(path, directory)
    assert not path.exists()


@pytest.mark.skipif(not hasattr(os, 'O_NOFOLLOW'), reason='Requires the appliance POSIX file boundary')
@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'public', 'directory', 'oversize', 'parent-alias'])
def test_private_request_rejects_unsafe_files(tmp_path, kind):
    directory = tmp_path / 'requests'
    directory.mkdir(mode=0o700)
    path = directory / ('enroll-' + 'a' * 32 + '.json')
    protected = tmp_path / 'protected'
    protected.write_text('must-not-be-read-or-unlinked')
    protected.chmod(0o600)
    if kind == 'symlink':
        path.symlink_to(protected)
    elif kind == 'hardlink':
        os.link(protected, path)
    elif kind == 'directory':
        path.mkdir(mode=0o700)
    elif kind == 'parent-alias':
        alias = tmp_path / 'alias'
        alias.symlink_to(directory, target_is_directory=True)
        directory = alias
        path = alias / path.name
    else:
        path.write_text('x' * (2049 if kind == 'oversize' else 1))
        path.chmod(0o644 if kind == 'public' else 0o600)
    with pytest.raises(ENROLL.ProtocolError, match='^Invalid private enrollment request$'):
        ENROLL.consume_request(path, directory)
    assert protected.read_text() == 'must-not-be-read-or-unlinked'


@pytest.mark.skipif(shutil.which('php') is None, reason='PHP validation runs in plugin CI and on OPNsense')
def test_php_independently_validates_selected_assignment_fields():
    cases = [SAMPLE, dict(SAMPLE, future_optional={'must_not_be_saved': True}), dict(SAMPLE, server_port=True),
             dict(SAMPLE, server_name='bad/path'), dict(SAMPLE, device_secret='A' * 42 + 'B'),
             dict(SAMPLE, agent_protocol_version='2.0.0'), dict(SAMPLE, relay_ca_pem='invalid')]
    program = r'''require $argv[1];
    $result=[];foreach(json_decode(stream_get_contents(STDIN),true) as $case){
        $v=\OPNsense\NetHubAgent\Enrollment::assignment($case);
        $result[]=['accepted'=>$v!==null,'keys'=>$v===null?[]:array_keys($v)];
    }echo json_encode($result);'''
    run = subprocess.run(['php', '-r', program, str(PHP)], input=json.dumps(cases), text=True, capture_output=True, check=True)
    result = json.loads(run.stdout)
    assert [item['accepted'] for item in result] == [True, True, False, False, False, False, False]
    assert 'future_optional' not in result[1]['keys']
    assert not run.stderr


@pytest.mark.skipif(shutil.which('php') is None, reason='Requires appliance PHP')
def test_php_controller_keeps_credentials_private_and_saves_under_native_lock(tmp_path):
    directory = tmp_path / 'requests'
    directory.mkdir(mode=0o700)
    controller = ROOT / 'agents/opnsense/plugin/src/usr/local/opnsense/mvc/app/controllers/OPNsense/NetHubAgent/Api/EnrollController.php'
    harness = ROOT / 'agents/opnsense/plugin/tests/enrollment_controller_contract.php'
    run = subprocess.run(['php', str(harness), str(controller), str(PHP), str(directory)],
                         input=json.dumps(SAMPLE), text=True, capture_output=True, check=True)
    assert json.loads(run.stdout)['controller_cases_passed'] == [
        'success', 'start-failed', 'bad-response', 'model-invalid', 'existing', 'get-only', 'readonly', 'busy', 'service-busy']
    assert not run.stderr


@pytest.fixture
def https_console(tmp_path):
    if shutil.which('openssl') is None:
        pytest.skip('Real TLS generation requires openssl; exercised in Linux CI')
    def run(args):
        subprocess.run(['openssl', *args], cwd=tmp_path, capture_output=True, check=True)
    run(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc', '-days', '1',
         '-keyout', 'ca-key.pem', '-out', 'ca.pem', '-subj', '/CN=fixture root',
         '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    run(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
         '-keyout', 'key.pem', '-out', 'server.csr', '-subj', '/CN=localhost'])
    (tmp_path / 'extensions').write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n')
    run(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca-key.pem', '-set_serial', '2',
         '-days', '1', '-out', 'cert.pem', '-extfile', 'extensions'])
    calls = []
    state = {'status': 201, 'body': json.dumps(SAMPLE).encode(), 'encoding': 'identity', 'length_extra': 0}
    state['ca_pem'] = (tmp_path / 'ca.pem').read_text()
    state['leaf_pem'] = (tmp_path / 'cert.pem').read_text()
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            calls.append((self.path, json.loads(body)))
            state.setdefault('authorizations', []).append(self.headers.get_all('Authorization', []))
            selected = state.get('responses', {}).get(self.path, state)
            payload = selected['body']
            self.send_response(selected['status'])
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Encoding', state['encoding'])
            self.send_header('Location', '/must-not-follow')
            self.send_header('Content-Length', str(len(payload) + state['length_extra']))
            self.end_headers()
            self.wfile.write(payload)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / 'cert.pem', tmp_path / 'key.pem')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, ssl.create_default_context(cafile=str(tmp_path / 'ca.pem')), calls, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_real_https_enrollment_ignores_environment_proxy_and_verifies_tls(https_console, monkeypatch):
    port, context, calls, state = https_console
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
    result = ENROLL.request_enrollment(f'https://localhost:{port}', 'A' * 43, '26.7.7', '0.0.3', 'router.local', context)
    assert result == SAMPLE
    assert calls[0][0] == '/api/v1/devices/enroll'
    assert calls[0][1]['enroll_token'] == 'A' * 43
    assert 'token' not in calls[0][0]
    for origin, roots in [(f'https://localhost:{port}', None), (f'https://127.0.0.1:{port}', context)]:
        with pytest.raises(ENROLL.ProtocolError, match='^Console HTTPS request failed;'):
            ENROLL.request_enrollment(origin, 'A' * 43, '26.7.7', '0.0.3', 'router.local', roots)
    assert len(calls) == 1


def test_overlapping_distinct_ca_roots_and_leaf_rejection(https_console):
    port, context, calls, state = https_console
    overlap = SAMPLE['relay_ca_pem'] + state['ca_pem']
    assert ENROLL.validate_ca(overlap) == overlap
    with pytest.raises(ENROLL.ProtocolError):
        ENROLL.validate_ca(state['leaf_pem'])


def test_real_https_lifecycle_authentication_and_verified_acknowledgement(https_console, monkeypatch):
    import lifecycle
    port, context, calls, state = https_console
    origin = f'https://localhost:{port}'
    device_id = SAMPLE['device_id']
    state['status'] = 200
    state['body'] = json.dumps({'agent_protocol_version': '1.0.0', 'device_id': device_id, 'revoked': True}).encode()
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
    assert lifecycle.request_removal(origin, 'A' * 43, device_id, context)['revoked'] is True
    assert calls == [('/api/v1/devices/unenroll', lifecycle.identity(device_id))]
    assert state['authorizations'] == [['Bearer ' + 'A' * 43]]
    with pytest.raises(ENROLL.ProtocolError):
        lifecycle.request_removal(origin, 'A' * 43, device_id)
    assert len(calls) == 1


@pytest.mark.parametrize('kind', ['redirect', 'oversize', 'duplicate', 'encoding', 'truncated'])
def test_real_https_rejects_redirect_and_bad_responses(https_console, kind):
    port, context, calls, state = https_console
    if kind == 'redirect':
        state['status'] = 302
    elif kind == 'oversize':
        state['body'] = b'x' * 65537
    elif kind == 'duplicate':
        state['body'] = b'{"device_secret":"first","device_secret":"second"}'
    elif kind == 'encoding':
        state['encoding'] = 'gzip'
    else:
        state['length_extra'] = 3
    with pytest.raises(ENROLL.ProtocolError):
        ENROLL.request_enrollment(f'https://localhost:{port}', 'A' * 43, '26.7.7', '0.0.3', 'router.local', context)
    assert len(calls) == 1
