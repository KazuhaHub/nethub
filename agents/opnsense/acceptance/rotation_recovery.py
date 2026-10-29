"""Recover actual committed replies and native saves after owned interruptions."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import time
import uuid

from guest import GuestError, invoke


def response_loss_config(original, *, unavailable=False):
    """Scope response interception to the exact public rotation endpoint."""
    boundary = '    @device path /api/v1/devices/*\n'
    if original.count(boundary) != 1 or 'handle_response' in original:
        raise GuestError('Unexpected owned edge configuration')
    interception = '''    handle /api/v1/devices/rotate {
        reverse_proxy nethub-authz:8081 {
            handle_response {
                abort
            }
        }
    }
'''
    if unavailable:
        interception = '''    handle /api/v1/devices/rotate {
        respond 503
    }
'''
    return original.replace(boundary, interception + boundary)


@contextmanager
def owned_edge_fault(stage, compose, *, unavailable=False):
    edge = invoke(compose + ['ps', '-q', 'caddy'], 'owned interrupted-rotation edge').decode().strip()
    if not re.fullmatch('[a-f0-9]{64}', edge):
        raise GuestError('Owned interrupted-rotation edge unavailable')
    path = Path(stage) / 'Caddyfile'
    if (path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1
            or path.stat().st_size > 65536):
        raise GuestError('Owned edge configuration storage changed')
    original = path.read_text(encoding='utf-8')
    changed = response_loss_config(original, unavailable=unavailable)

    def reload_config(value):
        # Preserve the bind-mounted file inode; replacing it would not change the
        # configuration visible to the already running owned container.
        with path.open('w', encoding='utf-8', newline='\n') as output:
            output.write(value)
            output.flush()
        invoke(['docker', 'exec', edge, 'caddy', 'reload', '--config', '/etc/caddy/Caddyfile',
                '--adapter', 'caddyfile'], 'owned interrupted-rotation edge reload')
        if invoke(compose + ['ps', '-q', 'caddy'], 'owned edge identity after reload').decode().strip() != edge:
            raise GuestError('Owned edge identity changed during interruption')

    try:
        reload_config(changed)
        yield
    finally:
        reload_config(original)


def exercise_response_loss(guest, stage, compose, page_action, native_read, sql, route,
                           device, stable_query, grants_query):
    before = native_read('native-response-loss-before.json')
    stable, grants = sql(stable_query), sql(grants_query)
    count_query = "SELECT count(*) FROM device_rotations WHERE device_id='" + device + "';"
    audit_query = ("SELECT count(*) FROM audit_log WHERE action='device.rotated' "
                   "AND target_device_id='" + device + "';")
    operations, audits = int(sql(count_query)), int(sql(audit_query))
    with owned_edge_fault(stage, compose):
        page_action('rotate', expected=False, label='rotate-lost')
        unchanged = native_read('native-response-loss-retained.json')
        raw = guest.ssh("cd /usr/local/opnsense/scripts/nethub-agent\n"
            "/usr/local/bin/python3.13 - <<'PY'\n"
            "import json\nfrom rotation import RotationJournal\n"
            "print(json.dumps(RotationJournal('/var/db/nethub-agent')._read()))\nPY\n",
            'private prepared native rotation readback')
        pending = json.loads(raw)
        operation = str(uuid.UUID(pending['operation_id']))
        candidate = pending['candidate']
        if (pending['phase'] != 'prepared' or pending['native_before'] != before or unchanged != before
                or operation != pending['operation_id'] or uuid.UUID(operation).version != 4
                or not isinstance(candidate, str) or not re.fullmatch('[A-Za-z0-9_-]{43}', candidate)):
            raise GuestError('Lost response did not retain the original prepared native operation')
        digest = hashlib.sha256(candidate.encode('ascii')).hexdigest()
        matching = sql("SELECT count(*) FROM device_rotations WHERE device_id='" + device
            + "' AND operation_id='" + operation + "' AND encode(candidate_digest,'hex')='" + digest + "';")
        if matching != '1' or int(sql(count_query)) != operations + 1 or int(sql(audit_query)) != audits + 1:
            raise GuestError('Lost reply was not bound to exactly one genuine committed operation')
    started = time.monotonic()
    page_action('rotate', expected=True, label='rotate-recovered')
    after = native_read('native-response-loss-after.json')
    if (after['device_secret'] != candidate or after['domain_claim'] == before['domain_claim']
            or any(after[key] != before[key] for key in before if key not in ('device_secret', 'domain_claim'))):
        raise GuestError('Unknown commit recovery did not apply its retained native candidate')
    guest.ssh('test ! -e /var/db/nethub-agent/rotation.json\n', 'completed native rotation journal removal')
    if (int(sql(count_query)) != operations + 1 or int(sql(audit_query)) != audits + 1
            or sql(stable_query) != stable or sql(grants_query) != grants):
        raise GuestError('Unknown commit retry changed operation count, identity or grants')
    for _ in range(30):
        if route():
            break
        time.sleep(1)
    else:
        raise GuestError('Unknown commit native recovery did not restore verified TLS')
    return ({'actual_committed_response_loss': True, 'prepared_native_journal_retained': True,
             'native_model_unchanged_during_ambiguity': True,
             'same_operation_and_candidate_recovered_by_native_page': True,
             'exactly_one_history_and_audit_record': True, 'completed_journal_removed': True,
             'identity_and_source_grants_retained': True, 'same_route_verified_TLS_recovered': True,
             'retry_to_verified_route_ms': round((time.monotonic() - started) * 1000)},
            [after['device_secret'], after['domain_claim']])


def exercise_save_interruption(guest, stage, compose, page_action, native_read, sql, route,
                               device, stable_query, grants_query, nonce, check_unavailable):
    before = native_read('native-save-interruption-before.json')
    stable, grants = sql(stable_query), sql(grants_query)
    count_query = "SELECT count(*) FROM device_rotations WHERE device_id='" + device + "';"
    audit_query = ("SELECT count(*) FROM audit_log WHERE action='device.rotated' "
                   "AND target_device_id='" + device + "';")
    operations, audits = int(sql(count_query)), int(sql(audit_query))
    guest.ssh('test ! -e /var/db/nethub-agent/rotation.json\n', 'clean received-operation fixture start')
    guest.put(Path(__file__).with_name('rotation-save-lock.php'), 'rotation-save-lock.php')
    request = Path(stage) / 'relay-test/native-save-lock-input.json'
    request.write_text(json.dumps({'nonce': nonce}), encoding='ascii')
    request.chmod(0o600)
    guest.put(request, request.name)
    guest.ssh('umask 077\nnohup /usr/bin/timeout -k 2 45 /usr/local/bin/php '
        '-d register_argc_argv=1 /root/nethub-ci/rotation-save-lock.php '
        '< /root/nethub-ci/native-save-lock-input.json '
        '> /root/nethub-ci/native-save-lock-result.json 2>&1 &\n', 'bounded owned native save lock')

    def wait_marker(name):
        if name not in ('ready', 'completed'):
            raise GuestError('Unknown native lock fixture marker')
        guest.ssh("/usr/local/bin/python3.13 - <<'PY'\n"
            "import pathlib,time\n"
            f"p=pathlib.Path('/root/nethub-ci/native-save-lock-{name}')\n"
            "end=time.monotonic()+10\n"
            "while not p.is_file() and time.monotonic()<end: time.sleep(.05)\n"
            "assert p.read_bytes()==b'1\\n'\nPY\n", 'owned native save lock ' + name)

    try:
        wait_marker('ready')
        page_action('rotate', expected=False, label='rotate-save-failed')
        raw = guest.ssh("/usr/local/bin/python3.13 - <<'PY'\n"
            "import json,pathlib,sys\n"
            "sys.path.insert(0,'/usr/local/opnsense/scripts/nethub-agent')\n"
            "from rotation import RotationJournal\n"
            "assert pathlib.Path('/root/nethub-ci/native-save-lock-acquired').read_bytes()==b'1\\n'\n"
            "print(json.dumps(RotationJournal('/var/db/nethub-agent')._read()))\nPY\n",
            'private received native rotation readback')
        pending = json.loads(raw)
        operation = str(uuid.UUID(pending['operation_id']))
        candidate = pending['candidate']
        if (pending['phase'] != 'received' or pending['native_before'] != before
                or operation != pending['operation_id'] or uuid.UUID(operation).version != 4
                or not isinstance(candidate, str) or not re.fullmatch('[A-Za-z0-9_-]{43}', candidate)):
            raise GuestError('Native save failure did not retain its received assignment')
    finally:
        guest.ssh('umask 077\nprintf "1\\n" > /root/nethub-ci/native-save-lock-release\n',
                  'owned native save lock release')
        wait_marker('completed')
    if native_read('native-save-interruption-retained.json') != before:
        raise GuestError('Native save interruption changed the original model')
    digest = hashlib.sha256(candidate.encode('ascii')).hexdigest()
    matching = sql("SELECT count(*) FROM device_rotations WHERE device_id='" + device
        + "' AND operation_id='" + operation + "' AND encode(candidate_digest,'hex')='" + digest + "';")
    if matching != '1' or int(sql(count_query)) != operations + 1 or int(sql(audit_query)) != audits + 1:
        raise GuestError('Received native assignment differs from its single committed operation')
    started = time.monotonic()
    with owned_edge_fault(stage, compose, unavailable=True):
        check_unavailable()
        page_action('rotate', expected=True, label='rotate-save-recovered')
    after = native_read('native-save-interruption-after.json')
    if (after['device_secret'] != candidate or after['domain_claim'] == before['domain_claim']
            or any(after[key] != before[key] for key in before if key not in ('device_secret', 'domain_claim'))):
        raise GuestError('Received assignment retry did not apply its retained native candidate')
    guest.ssh('test ! -e /var/db/nethub-agent/rotation.json\n', 'received native operation completed')
    if (int(sql(count_query)) != operations + 1 or int(sql(audit_query)) != audits + 1
            or sql(stable_query) != stable or sql(grants_query) != grants):
        raise GuestError('Received assignment retry changed operation count, identity or grants')
    for _ in range(30):
        if route():
            break
        time.sleep(1)
    else:
        raise GuestError('Received native recovery did not restore verified TLS')
    return ({'actual_native_configuration_lock_interruption': True,
             'received_assignment_retained': True, 'native_model_unchanged_before_retry': True,
             'same_candidate_recovered_by_native_page': True, 'completed_journal_removed': True,
             'received_retry_with_rotation_endpoint_unavailable': True,
             'exactly_one_history_and_audit_record': True, 'identity_and_source_grants_retained': True,
             'same_route_verified_TLS_recovered': True,
             'retry_to_verified_route_ms': round((time.monotonic() - started) * 1000)},
            [after['device_secret'], after['domain_claim']])
