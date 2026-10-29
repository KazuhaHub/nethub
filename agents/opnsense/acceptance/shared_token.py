"""Verify native Rotate after a real bound shared-token host cutover."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import uuid

from guest import GuestError


def validate_native_replacement(before, after):
    changed = {'frp_token', 'device_secret', 'domain_claim'}
    if (set(before) != set(after) or not changed.issubset(before)
            or any(not isinstance(after[key], str) or not after[key] or after[key] == before[key] for key in changed)
            or any(after[key] != before[key] for key in before if key not in changed)):
        raise GuestError('Shared-token native rotation changed policy or retained old credentials')


def exercise_shared_token(stage, project, evidence, native_read, page_action, route, inspect_gui,
                          expected_gui, sql, stable_query, grants_query, request, other,
                          refresh_witness, witness_route):
    stage, evidence = Path(stage), Path(evidence)
    before = native_read('native-before-shared.json')
    identity, grants = sql(stable_query), sql(grants_query)
    witness_id = str(uuid.UUID(other['device_id']))
    witness_query = ("SELECT jsonb_build_array(id,tenant_id,owner_user_id,subdomain,gui_public_key,enrolled_at)::text "
                     "FROM devices WHERE id='" + witness_id + "';")
    witness_grants = "SELECT source_ip::text||expires_at::text FROM device_access_grants WHERE device_id='" + witness_id + "' ORDER BY source_ip;"
    original_witness, original_grants = sql(witness_query), sql(witness_grants)
    if not route() or not witness_route():
        raise GuestError('Both native incident routes must work before host cutover')
    environment = dict(os.environ, NETHUB_TEST_TOKEN_DEPLOYMENT=str(stage / 'deployment'),
        NETHUB_TEST_TOKEN_PROJECT=project, NETHUB_TEST_TOKEN_COMPOSE=str(stage / 'test.yml'),
        NETHUB_TEST_TOKEN_CLI=str(stage / 'http01-nethub'), NETHUB_TEST_TOKEN_RUNTIME_LABEL='native')
    result = subprocess.run([str(stage / 'setup.test'), '-test.v', '-test.run', '^TestNativeRelayTokenRuntimeCLI$',
        '-test.timeout=240s'], env=environment, capture_output=True, timeout=250)
    output = result.stdout + result.stderr
    path = stage / 'relay-test/native-shared-token-runtime-private.log'
    path.write_bytes(output)
    path.chmod(0o600)
    for value in (before['frp_token'], before['device_secret'], before['domain_claim'],
                  other['device_secret'], other['domain_claim']):
        if value.encode('ascii') in output:
            raise GuestError('Host token command output disclosed a retained credential')
    text = output.decode('utf-8')
    if (result.returncode or text.count('--- PASS: TestNativeRelayTokenRuntimeCLI (') != 1
            or '--- SKIP:' in text or '--- FAIL:' in text or not text.rstrip().endswith('PASS')):
        phase = 'unclassified'
        try:
            failed = json.loads((stage / 'relay-test/shared-token-runtime-native.json').read_text(encoding='utf-8'))
            if (set(failed) == {'passed', 'phase'} and failed['passed'] is False
                    and failed['phase'] in ('runtime_binding', 'original_input', 'durable_reload_interrupt',
                                            'resume', 'published_runtime', 'complete_retry', 'superseded_refusal')):
                phase = failed['phase']
        except (OSError, ValueError, TypeError):
            pass
        path = evidence / 'installed-shared-token.json'
        path.write_text(json.dumps({'passed': False, 'host_phase': phase}), encoding='utf-8')
        path.chmod(0o600)
        raise GuestError('Native incident host cutover failed at ' + phase)
    host = json.loads((stage / 'relay-test/shared-token-runtime-native.json').read_text(encoding='utf-8'))
    if (host.get('passed') is not True or host.get('actual_compiled_server_token_command') is not True
            or host.get('actual_SIGTERM_during_durable_reload_resumed_same_candidate') is not True
            or host.get('superseded_complete_operation_refused_without_rollback') is not True
            or host.get('online_or_native_fleet_recovery_accepted') is not False):
        raise GuestError('Native incident host cutover receipt unavailable')
    started = time.monotonic()
    page_action('rotate', label='rotate-shared')
    after = native_read('native-after-shared.json')
    validate_native_replacement(before, after)
    if (sql(stable_query) != identity or sql(grants_query) != grants or inspect_gui() != expected_gui):
        raise GuestError('Native incident changed device identity, grants or GUI security')
    deadline = time.monotonic() + 30
    while not route():
        if time.monotonic() >= deadline:
            raise GuestError('Native shared-token assigned route did not recover verified TLS')
        time.sleep(.5)
    native_ms = round((time.monotonic() - started) * 1000)
    request('/api/v1/devices/rotate', {'agent_protocol_version': '1.6.0', 'device_id': before['device_id'],
        'operation_id': str(uuid.uuid4()), 'replacement_secret': before['device_secret'],
        'expected_relay_ca_sha256': hashlib.sha256(base64.b64decode(before['relay_ca'], validate=True)).hexdigest()},
        secret=before['device_secret'], expected=401)
    def rotate_reference(previous):
        operation, candidate = str(uuid.uuid4()), secrets.token_urlsafe(32)
        body = {'agent_protocol_version': '1.6.0', 'device_id': previous['device_id'], 'operation_id': operation,
            'replacement_secret': candidate, 'expected_relay_ca_sha256': hashlib.sha256(previous['relay_ca_pem'].encode('ascii')).hexdigest()}
        replacement = request('/api/v1/devices/rotate', body, secret=previous['device_secret'])
        if (replacement['frp_token'] != after['frp_token'] or replacement['frp_token'] == previous['frp_token']
                or replacement['device_secret'] != candidate or replacement['operation_id'] != operation
                or any(replacement.get(key) != previous.get(key) for key in
                       ('device_id', 'subdomain', 'server_addr', 'server_port', 'server_name', 'relay_ca_pem', 'gui_key_fingerprint'))
                or request('/api/v1/devices/rotate', body, secret=candidate) != replacement):
            raise GuestError('Independent incident fixture did not receive a stable replacement')
        request('/api/v1/devices/rotate', body, secret=previous['device_secret'], expected=401)
        return replacement

    replacement = rotate_reference(other)
    refresh_witness(replacement)
    path = stage / 'relay-test/assignment1.json'
    path.write_text(json.dumps(replacement), encoding='utf-8')
    path.chmod(0o600)
    # Preserve the other retained reference assignment for the later authority
    # harness; this is fixture preparation, not an offline native recovery claim.
    path = stage / 'relay-test/assignment0.json'
    retained = json.loads(path.read_text(encoding='utf-8'))
    replacement_first = rotate_reference(retained)
    path.write_text(json.dumps(replacement_first), encoding='utf-8')
    path.chmod(0o600)
    deadline = time.monotonic() + 30
    while not witness_route():
        if time.monotonic() >= deadline:
            raise GuestError('Independent incident witness route did not recover verified TLS')
        time.sleep(.5)
    if (not route() or sql(witness_query) != original_witness or sql(witness_grants) != original_grants
            or sql(stable_query) != identity or sql(grants_query) != grants):
        raise GuestError('Incident recovery changed identity/grants or lost the native route')
    outcome = {'passed': True, 'actual_host_cutover': host, 'actual_native_page_Rotate_after_host_cutover': True,
        'native_stored_bearer_used_without_new_enrollment_token': True,
        'native_token_bearer_and_claim_replaced_with_policy_retained': True,
        'native_GUI_key_checks_and_exact_alias_retained': True,
        'native_and_independent_witness_identity_and_source_grants_retained': True,
        'both_original_assigned_routes_verified_TLS_recovered': True,
        'native_old_device_bearer_HTTP_401': True, 'native_rotation_to_verified_route_ms': native_ms,
        'public_network_offline_fleet_or_formal_release_acceptance': False}
    path = evidence / 'installed-shared-token.json'
    path.write_text(json.dumps(outcome), encoding='utf-8')
    path.chmod(0o600)
    return outcome, (before['device_secret'], before['domain_claim'], before['frp_token'],
                     after['device_secret'], after['domain_claim'], after['frp_token'],
                     replacement['device_secret'], replacement['domain_claim'], replacement_first['device_secret'])
