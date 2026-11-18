"""Observe one genuine installed failure, normal delivery and exact replay."""
from datetime import datetime
import json
import os
from pathlib import Path
import re
import time
import uuid

from guest import GuestError, invoke
from package_migration import owned
from package_probe import validate as validate_probe


PHASES = ('baseline', 'failure', 'report', 'ledger', 'replay', 'browser', 'recovery', 'completed')
FLAGS = ('candidate_refused', 'template_restored', 'original_outbox_acknowledged',
         'one_immutable_event_and_audit', 'exact_replay_did_not_duplicate_audit',
         'actual_Web_projection_verified', 'normal_browser_audit_verified',
         'recovered_without_restart', 'native_identity_GUI_trust_process_and_control_retained',
         'source_grants_and_independent_original_control_retained')
BUSY = {'available': False, 'reason': 'mutation_busy'}
# Covers the longest documented cron lock holder (trust run_bounded, 95 s).
BUSY_DEADLINE = 100
LIMITS = ('public_or_formal_bad_canary_accepted', 'full_W5_W7_or_release_accepted')


def validate(value):
    fields = set(FLAGS + LIMITS) | {'version', 'passed', 'phase', 'source_head', 'event_count',
                                   'explicit_normal_reconcile_calls'}
    counters = ('mutation_busy_retries', 'max_busy_wait_ms')
    if isinstance(value, dict) and value.get('version') == 2:
        fields |= set(counters)
    if (not isinstance(value, dict) or set(value) != fields
            or type(value['version']) is not int or value['version'] not in (1, 2)
            or value['version'] == 2 and any(type(value[key]) is not int or value[key] < 0 for key in counters)
            or type(value['passed']) is not bool or value['phase'] not in PHASES
            or not isinstance(value['source_head'], str) or not re.fullmatch('[a-f0-9]{40}', value['source_head'])
            or type(value['event_count']) is not int or value['event_count'] not in (0, 1)
            or type(value['explicit_normal_reconcile_calls']) is not int
            or not 0 <= value['explicit_normal_reconcile_calls'] <= 2
            or any(type(value[key]) is not bool for key in FLAGS + LIMITS)
            or any(value[key] for key in LIMITS)):
        raise ValueError('Unexpected installed reconcile audit evidence')
    if value['passed'] != (value['phase'] == 'completed') or value['passed'] and (
            not all(value[key] for key in FLAGS) or value['event_count'] != 1
            or value['explicit_normal_reconcile_calls'] != 2):
        raise ValueError('Incomplete installed reconcile audit evidence')


def original_event(value, device):
    """Validate private values before using their bounded canonical SQL forms."""
    if (not isinstance(value, dict) or set(value) != {'device_id', 'events', 'candidate_refused',
            'template_restored', 'native_cli_exit'} or value['device_id'] != device
            or value['candidate_refused'] is not True or value['template_restored'] is not True
            or type(value['native_cli_exit']) is not int or value['native_cli_exit'] != 1
            or not isinstance(value['events'], list) or len(value['events']) != 1):
        raise ValueError('Single genuine failure and restored template required')
    event = value['events'][0]
    if (not isinstance(event, dict) or set(event) != {'event_id', 'kind', 'count', 'first_at', 'last_at'}
            or event['kind'] != 'reconcile_failed' or type(event['count']) is not int or event['count'] != 1
            or not isinstance(event['event_id'], str)
            or str(uuid.UUID(event['event_id'], version=4)) != event['event_id']):
        raise ValueError('Original ordinary failure event required')
    for key in ('first_at', 'last_at'):
        stamp = event[key]
        if not isinstance(stamp, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z', stamp):
            raise ValueError('Canonical device-reported time required')
        datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%S.%fZ')
    if event['first_at'] != event['last_at']:
        raise ValueError('One original failure instant required')
    return event


def projection(page, event, device):
    if not isinstance(page, dict) or not isinstance(page.get('items'), list) or not 1 <= len(page['items']) <= 200:
        raise ValueError('Bounded actual filtered Web audit rows required')
    matches = []
    for row in page['items']:
        if not isinstance(row, dict) or not isinstance(row.get('details'), dict):
            raise ValueError('Actual typed Web audit row required')
        first = row['details'].get('first_reported_at')
        if isinstance(first, str) and datetime.fromisoformat(first) == datetime.fromisoformat(event['first_at']):
            matches.append(row)
    if len(matches) != 1:
        raise ValueError('One original device-reported failure row required')
    item = matches[0]
    details = item.get('details')
    if (item.get('action') != 'device.reconcile_failed' or item.get('target_device_id') != device
            or item.get('actor_type') != 'device' or not isinstance(details, dict)
            or set(details) != {'failure_count', 'device_reported', 'first_reported_at', 'last_reported_at'}
            or details['failure_count'] != '1' or details['device_reported'] is not True):
        raise ValueError('Narrow device-reported Web projection required')
    for public, private in (('first_reported_at', 'first_at'), ('last_reported_at', 'last_at')):
        if (not isinstance(details[public], str)
                or datetime.fromisoformat(details[public]) != datetime.fromisoformat(event[private])):
            raise ValueError('Actual Web projection changed the original device time')
    return details


def history(sql, device):
    query = "SELECT jsonb_build_object('events',(SELECT count(*) FROM device_reconcile_events WHERE device_id='" + device + "')," \
        "'audits',(SELECT count(*) FROM audit_log WHERE target_device_id='" + device + "' AND action IN ('device.reconcile_failed','device.reconcile_overflow')))::text;"
    value = json.loads(sql(query))
    if (not isinstance(value, dict) or set(value) != {'events', 'audits'}
            or any(type(number) is not int or number < 0 for number in value.values())):
        raise ValueError('Original retained failure history required')
    return value


def ledger(sql, device, event, baseline):
    # Both identifiers and times have already passed canonical closed validation.
    query = "SELECT jsonb_build_object('events',(SELECT count(*) FROM device_reconcile_events WHERE device_id='" + device + "')," \
        "'exact_event',(SELECT count(*) FROM device_reconcile_events WHERE device_id='" + device + "' AND event_id='" + event['event_id'] + "' " \
        "AND kind='reconcile_failed' AND failure_count=1 AND first_at='" + event['first_at'] + "' AND last_at='" + event['last_at'] + "')," \
        "'audits',(SELECT count(*) FROM audit_log WHERE target_device_id='" + device + "' AND action IN ('device.reconcile_failed','device.reconcile_overflow'))," \
        "'exact_audit',(SELECT count(*) FROM audit_log WHERE target_device_id='" + device + "' AND actor_type='device' AND actor_id='" + device + "' " \
        "AND action='device.reconcile_failed' AND payload=jsonb_build_object('event_id','" + event['event_id'] + "'::uuid," \
        "'failure_count',1,'device_reported',true,'first_reported_at','" + event['first_at'] + "'::timestamptz," \
        "'last_reported_at','" + event['last_at'] + "'::timestamptz)))::text;"
    value = json.loads(sql(query))
    if (value != {'events': baseline['events'] + 1, 'exact_event': 1,
                  'audits': baseline['audits'] + 1, 'exact_audit': 1}
            or any(type(number) is not int for number in value.values())):
        raise GuestError('Original failure receipt and audit were not retained exactly once')
    return value


def exercise(guest, stage, evidence, nonce, device, port, sql, request,
             gui_read, route, check_database, check_witness):
    owned(guest)
    if (not isinstance(device, str) or str(uuid.UUID(device)) != device
            or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise GuestError('Original owned enrollment and fixture nonce required')
    return _exercise(guest, Path(stage), Path(evidence), nonce, device, port, sql, request,
                     gui_read, route, check_database, check_witness)


def _exercise(guest, stage, evidence, nonce, device, port, sql, request,
              gui_read, route, check_database, check_witness):
    value = dict.fromkeys(FLAGS + LIMITS, False)
    value.update(version=2, passed=False, phase='baseline', source_head=os.environ['NETHUB_SOURCE_HEAD'],
                 event_count=0, explicit_normal_reconcile_calls=0, mutation_busy_retries=0, max_busy_wait_ms=0)
    path = evidence / 'installed-reconcile-audit.json'
    with path.open('x') as output:
        json.dump(value, output)
    path.chmod(0o600)

    def action(name):
        # Only the exact busy answer is retried; the probe makes it before any side effect.
        started = time.monotonic()
        while True:
            result = json.loads(guest.ssh('/usr/local/bin/python3.13 /root/nethub-ci/reconcile_failure_probe.py '
                + name + ' ' + nonce + '\n', 'owned native failure audit ' + name, timeout=60))
            if result != BUSY:
                return result
            waited = time.monotonic() - started
            value['mutation_busy_retries'] += 1
            value['max_busy_wait_ms'] = max(value['max_busy_wait_ms'], int(waited * 1000))
            if waited >= BUSY_DEADLINE:
                raise GuestError('Owned native failure audit lock remained busy')
            time.sleep(1)  # Holders keep the lock for seconds; avoid SSH connection churn.

    def probe():
        result = json.loads(guest.ssh_read_only_inspection(
            '/usr/local/bin/python3.13 /root/nethub-ci/package_probe.py ' + nonce + '\n'))
        validate_probe(result)
        return result

    def continuity():
        if probe() != baseline or gui_read() != gui or not route():
            raise GuestError('Failure audit changed the original native identity, process, GUI or route')
        check_database()
        check_witness()

    try:
        baseline, gui = probe(), gui_read()
        if (baseline['package_version'] != '0.0.21' or baseline['profile'] != [1, 3]
                or any(baseline['markers'].values()) or not baseline['running'] or not baseline['control_sha256']):
            raise GuestError('Clean current installed process and control required')
        if action('pending') != {'device_id': device, 'events': []}:
            raise GuestError('Unrelated retained failures must not be mixed with the native drill')
        retained = history(sql, device)
        continuity()
        value['phase'] = 'failure'
        first = None
        value['explicit_normal_reconcile_calls'] = 1
        try:
            failure = action('failure')
        except Exception as error:
            first = error
        try:
            if action('restore') != {'restored': True}:
                raise GuestError('Original failure template restoration not confirmed')
            value['template_restored'] = True
        except Exception:
            if first is not None:
                raise first
            raise
        if first is not None:
            raise first
        event = original_event(failure, device)
        value.update(candidate_refused=True, event_count=1)
        continuity()
        value['phase'] = 'report'
        # The normal scheduler can already have acknowledged the exact event.
        # This is still one normal report, not a synthetic SQL/event insertion.
        guest.ssh('/usr/local/sbin/configctl nethub-agent report\n', 'normal installed health and audit report', timeout=45)
        if action('pending') != {'device_id': device, 'events': []}:
            raise GuestError('Normal reporting did not acknowledge the original outbox')
        value['original_outbox_acknowledged'] = True
        continuity()
        value['phase'] = 'ledger'
        original = ledger(sql, device, event, retained)
        value['one_immutable_event_and_audit'] = True
        page = request('/api/v1/console/audit?action=device.reconcile_failed&device_id=' + device)
        details = projection(page, event, device)
        value['actual_Web_projection_verified'] = True
        value['phase'] = 'replay'
        if action('replay') != {'replayed': True, 'event_count': 1} or ledger(sql, device, event, retained) != original:
            raise GuestError('Exact original failure replay changed retained history')
        projection(request('/api/v1/console/audit?action=device.reconcile_failed&device_id=' + device), event, device)
        value['exact_replay_did_not_duplicate_audit'] = True
        continuity()
        value['phase'] = 'browser'
        config = stage / 'relay-test/native-reconcile-audit-browser-private.json'
        config.write_text(json.dumps({'console_port': port, 'device_id': device, 'details': details,
            'password_file': str(stage / 'admin-password'), 'evidence': str(evidence)}))
        config.chmod(0o600)
        invoke([os.environ['NETHUB_NODE_BINARY'], str(Path(__file__).with_name('console-audit-browser.mjs')),
                str(config)], 'normal console audit of genuine installed failure', timeout=90)
        browser = json.loads((evidence / 'installed-reconcile-audit-browser.json').read_text())
        validate_browser(browser)
        if not browser['passed']:
            raise GuestError('Normal browser did not confirm the original installed audit')
        value['normal_browser_audit_verified'] = True
        value['phase'] = 'recovery'
        value['explicit_normal_reconcile_calls'] = 2
        if action('recover') != {'recovered_without_restart': True, 'native_cli_exit': 0}:
            raise GuestError('Restored native configuration did not reconcile unchanged')
        guest.ssh('/usr/local/sbin/configctl nethub-agent report\n', 'normal installed recovered health report', timeout=45)
        if action('pending') != {'device_id': device, 'events': []} or ledger(sql, device, event, retained) != original:
            raise GuestError('Recovery created another event or lost retained history')
        continuity()
        value.update(recovered_without_restart=True, native_identity_GUI_trust_process_and_control_retained=True,
                     source_grants_and_independent_original_control_retained=True, passed=True, phase='completed')
        return value
    finally:
        validate(value)
        path.write_text(json.dumps(value, indent=2) + '\n')


def validate_browser(value):
    proofs = {'normal_login', 'filtered_original_device_reported_row', 'typed_count_and_interval_visible',
              'browser_integrity'}
    fields = proofs | {'version', 'passed', 'phase', 'isolated_console_CA_exception', 'public_network_acceptance'}
    if (not isinstance(value, dict) or set(value) != fields
            or type(value['version']) is not int or value['version'] != 1
            or type(value['passed']) is not bool or value['phase'] not in ('login', 'audit', 'integrity', 'completed')
            or any(type(value[key]) is not bool for key in proofs)
            or value['isolated_console_CA_exception'] is not True or value['public_network_acceptance'] is not False
            or value['passed'] != (value['phase'] == 'completed')
            or value['passed'] and not all(value[key] for key in proofs)):
        raise ValueError('Unexpected installed audit browser evidence')


def require_evidence(evidence, native):
    path = Path(evidence)
    value = json.loads((path / 'installed-reconcile-audit.json').read_text())
    validate(value)
    browser = json.loads((path / 'installed-reconcile-audit-browser.json').read_text())
    validate_browser(browser)
    if not value['passed'] or not browser['passed'] or native.get('installed_reconcile_audit') != value:
        raise GuestError('Installed reconcile audit and actual browser proof missing')
    image = path / 'installed-reconcile-audit.png'
    if image.is_symlink() or not image.is_file() or not 8 < image.stat().st_size <= 8 * 1024**2:
        raise GuestError('Original installed audit browser view missing')
    with image.open('rb') as stream:
        if stream.read(8) != b'\x89PNG\r\n\x1a\n':
            raise GuestError('Original installed audit browser view malformed')
