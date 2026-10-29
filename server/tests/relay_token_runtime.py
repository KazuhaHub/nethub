"""Exercise real host cutover, then refresh both online reference clients."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import uuid


def exercise_token_runtime(stage, port, project, assignments, clients, start_client, stop_client,
                           backend_port, check_tunnels, sql):
    stage = Path(stage)
    work = stage / 'shared-token-test'
    work.mkdir(mode=0o700)
    before = [dict(assignment) for assignment in assignments]
    if len(before) != 2 or any(client.poll() is not None for client in clients):
        raise RuntimeError('Two online original clients required before shared token replacement')
    identities = [sql("SELECT jsonb_build_array(id,tenant_id,owner_user_id,subdomain,gui_public_key,enrolled_at)::text "
                      "FROM devices WHERE id='" + str(uuid.UUID(item['device_id'])) + "';") for item in before]
    grants = [sql("SELECT source_ip::text||expires_at::text FROM device_access_grants WHERE device_id='" +
                  str(uuid.UUID(item['device_id'])) + "' ORDER BY source_ip;") for item in before]
    check_tunnels()
    environment = dict(os.environ, NETHUB_TEST_TOKEN_DEPLOYMENT=str(stage / 'deployment'),
                       NETHUB_TEST_TOKEN_PROJECT=project, NETHUB_TEST_TOKEN_COMPOSE=str(stage / 'test.yml'),
                       NETHUB_TEST_TOKEN_CLI=str(stage / 'http01-nethub'), NETHUB_TEST_TOKEN_RUNTIME_LABEL='reference')
    result = subprocess.run([str(stage / 'setup.test'), '-test.v', '-test.run', '^TestNativeRelayTokenRuntimeCLI$',
                             '-test.timeout=240s'], env=environment, capture_output=True, timeout=250)
    output = result.stdout + result.stderr
    log = stage / 'relay-test/shared-token-runtime-private.log'
    log.write_bytes(output)
    log.chmod(0o600)
    for item in before:
        for key in ('device_secret', 'frp_token', 'domain_claim'):
            if item[key].encode('ascii') in output:
                raise RuntimeError('Host token operation output disclosed a credential')
    text = output.decode('utf-8')
    if (result.returncode or text.count('--- PASS: TestNativeRelayTokenRuntimeCLI (') != 1
            or '--- SKIP:' in text or '--- FAIL:' in text or not text.rstrip().endswith('PASS')):
        phase = 'unclassified'
        try:
            failed = json.loads((stage / 'relay-test/shared-token-runtime-reference.json').read_text(encoding='utf-8'))
            if (set(failed) == {'passed', 'phase'} and failed['passed'] is False
                    and failed['phase'] in ('runtime_binding', 'original_input', 'durable_reload_interrupt',
                                            'resume', 'published_runtime', 'complete_retry', 'superseded_refusal')):
                phase = failed['phase']
        except (OSError, ValueError, TypeError):
            pass
        raise RuntimeError('Actual compiled shared token cutover receipt missing at ' + phase)
    host = json.loads((stage / 'relay-test/shared-token-runtime-reference.json').read_text(encoding='utf-8'))
    if (host.get('passed') is not True or host.get('actual_compiled_server_token_command') is not True
            or host.get('actual_SIGTERM_during_durable_reload_resumed_same_candidate') is not True
            or host.get('online_or_native_fleet_recovery_accepted') is not False):
        raise RuntimeError('Closed host token replacement outcome missing')
    started = time.monotonic()
    for index, previous in enumerate(before):
        candidate, operation = secrets.token_urlsafe(32), str(uuid.uuid4())
        body = {'agent_protocol_version': '1.6.0', 'device_id': previous['device_id'],
                'operation_id': operation, 'replacement_secret': candidate,
                'expected_relay_ca_sha256': hashlib.sha256(previous['relay_ca_pem'].encode('ascii')).hexdigest()}
        payload, header = work / f'request{index}.json', work / f'authorization{index}'
        payload.write_text(json.dumps(body), encoding='utf-8')
        payload.chmod(0o600)

        def rotate(secret, expected):
            header.write_text('Authorization: Bearer ' + secret + '\n', encoding='ascii')
            header.chmod(0o600)
            response = subprocess.run(['curl', '--silent', '--noproxy', '*', '--max-time', '10',
                '--cacert', str(stage / 'console-ca.pem'), '--connect-to',
                f'console.example.com:443:127.0.0.1:{port}', '-H', '@' + str(header),
                '-H', 'Content-Type: application/json', '--data-binary', '@' + str(payload),
                '--write-out', '\n%{http_code}', 'https://console.example.com/api/v1/devices/rotate'],
                capture_output=True, timeout=12)
            raw, _, status = response.stdout.rpartition(b'\n')
            if response.returncode or status != str(expected).encode():
                raise RuntimeError('Online device rotation HTTP outcome differed after host cutover')
            if expected != 200 and (secret.encode('ascii') in raw or candidate.encode('ascii') in raw):
                raise RuntimeError('Online rotation refusal disclosed a credential')
            return json.loads(raw)

        replacement = rotate(previous['device_secret'], 200)
        if (replacement['operation_id'] != operation or replacement['device_secret'] != candidate
                or replacement['frp_token'] == previous['frp_token']
                or replacement['domain_claim'] == previous['domain_claim']
                or any(replacement.get(key) != previous.get(key) for key in
                       ('device_id', 'subdomain', 'server_addr', 'server_port', 'server_name', 'relay_ca_pem', 'gui_key_fingerprint'))):
            raise RuntimeError('Online replacement changed identity/trust or retained the compromised token')
        if rotate(candidate, 200) != replacement:
            raise RuntimeError('Online candidate replay changed its assignment')
        rotate(previous['device_secret'], 401)
        stop_client(clients[index])
        clients[index] = start_client(replacement, f'shared-token-client{index}', backend_port)
        assignments[index] = replacement
        path = stage / f'relay-test/assignment{index}.json'
        temporary = work / f'assignment{index}-next.json'
        temporary.write_text(json.dumps(replacement), encoding='utf-8')
        temporary.chmod(0o600)
        os.replace(temporary, path)
        device = str(uuid.UUID(previous['device_id']))
        if (sql("SELECT jsonb_build_array(id,tenant_id,owner_user_id,subdomain,gui_public_key,enrolled_at)::text "
                "FROM devices WHERE id='" + device + "';") != identities[index]
                or sql("SELECT source_ip::text||expires_at::text FROM device_access_grants WHERE device_id='" + device +
                       "' ORDER BY source_ip;") != grants[index]):
            raise RuntimeError('Online shared token rotation changed identity or source grants')
    if assignments[0]['frp_token'] != assignments[1]['frp_token']:
        raise RuntimeError('Online devices received different shared relay tokens')
    check_tunnels()
    outcome = {'passed': True, 'actual_compiled_host_cutover': host,
               'two_online_devices_rotated_with_existing_bearers': True,
               'same_candidates_replayed_and_old_bearers_refused': True,
               'identity_source_grants_and_public_trust_retained': True,
               'both_same_assigned_routes_verified_TLS_recovered': True,
               'online_rotation_and_recovery_ms': round((time.monotonic() - started) * 1000),
               'native_fleet_or_public_network_acceptance': False}
    (stage / 'relay-test/shared-token-incident-result.json').write_text(json.dumps(outcome), encoding='utf-8')
    print(json.dumps({'shared_token_incident': outcome}), flush=True)
