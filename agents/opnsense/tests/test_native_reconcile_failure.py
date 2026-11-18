"""Reject incomplete native audit chains without repeating any mutation."""
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/reconcile_failure.py'
sys.path.insert(0, str(SOURCE.parent))
try:
    SPEC = importlib.util.spec_from_file_location('native_reconcile_failure_test', SOURCE)
    audit = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(audit)
finally:
    sys.path.pop(0)

DEVICE = '11111111-1111-4111-8111-111111111111'
EVENT = {'event_id': '22222222-2222-4222-8222-222222222222', 'kind': 'reconcile_failed',
         'count': 1, 'first_at': '2026-11-16T00:00:00.123456Z', 'last_at': '2026-11-16T00:00:00.123456Z'}
FAILURE = {'device_id': DEVICE, 'events': [EVENT], 'candidate_refused': True,
           'template_restored': True, 'native_cli_exit': 1}
DETAILS = {'failure_count': '1', 'device_reported': True,
           'first_reported_at': EVENT['first_at'], 'last_reported_at': EVENT['last_at']}
PAGE = {'items': [{'action': 'device.reconcile_failed', 'target_device_id': DEVICE,
                   'actor_type': 'device', 'details': DETAILS}]}


def browser_result():
    return {'version': 1, 'passed': True, 'phase': 'completed', 'normal_login': True,
            'filtered_original_device_reported_row': True, 'typed_count_and_interval_visible': True,
            'browser_integrity': True, 'isolated_console_CA_exception': True,
            'public_network_acceptance': False}


class Guest:
    def __init__(self):
        self.calls = []
        self.pending = []
        self.changed = False
        self.failure = None
        self.restore_refused = False

    def ssh(self, script, *_args, **_kwargs):
        if 'configctl' in script:
            action = 'report'
            self.pending = []
        else:
            action = script.split()[-2]
        self.calls.append(action)
        if action == 'failure':
            if self.failure:
                raise self.failure
            self.pending = [EVENT]
            value = copy.deepcopy(FAILURE)
        elif action == 'restore':
            if self.restore_refused:
                raise audit.GuestError('second restore failure')
            value = {'restored': True}
        elif action == 'pending':
            value = {'device_id': DEVICE, 'events': self.pending}
        elif action == 'replay':
            value = {'replayed': True, 'event_count': 1}
        elif action == 'recover':
            value = {'recovered_without_restart': True, 'native_cli_exit': 0}
        else:
            value = {}
        return json.dumps(value).encode()

    def ssh_read_only_inspection(self, _script):
        value = dict.fromkeys(audit.validate_probe.__globals__['HASHES'], 'a' * 64)
        value.update(version=1, package_version='0.0.23', profile=[1, 3],
            markers=dict.fromkeys(audit.validate_probe.__globals__['MARKERS'], False), running=True,
            pid=124, process_sha256='b' * 64, control_sha256=('d' if self.changed else 'c') * 64)
        return json.dumps(value).encode()


@pytest.fixture
def case(monkeypatch, tmp_path):
    stage, evidence = tmp_path / 'stage', tmp_path / 'evidence'
    (stage / 'relay-test').mkdir(parents=True)
    evidence.mkdir()
    monkeypatch.setenv('NETHUB_SOURCE_HEAD', 'a' * 40)
    monkeypatch.setenv('NETHUB_NODE_BINARY', '/fixture/node')
    guest = Guest()
    checks = []

    def invoke(argv, _label, **_kwargs):
        assert argv[0] == '/fixture/node' and argv[1].endswith('console-audit-browser.mjs')
        config = json.loads(Path(argv[2]).read_text())
        assert config['details'] == DETAILS and config['device_id'] == DEVICE
        assert Path(argv[2]).stat().st_mode & 0o777 == 0o600
        (evidence / 'installed-reconcile-audit-browser.json').write_text(json.dumps(browser_result()))
        (evidence / 'installed-reconcile-audit.png').write_bytes(b'\x89PNG\r\n\x1a\nfixture')
        checks.append('browser')

    monkeypatch.setattr(audit, 'invoke', invoke)

    def sql(query):
        assert 'INSERT' not in query and 'UPDATE' not in query and 'DELETE' not in query
        assert DEVICE in query
        if 'exact_event' not in query:
            checks.append('history')
            return json.dumps({'events': 2, 'audits': 2})
        assert EVENT['event_id'] in query
        checks.append('ledger')
        return json.dumps({'events': 3, 'audits': 3, 'exact_event': 1, 'exact_audit': 1})

    def request(path):
        assert path == '/api/v1/console/audit?action=device.reconcile_failed&device_id=' + DEVICE
        checks.append('Web')
        return copy.deepcopy(PAGE)

    def exercise():
        return audit._exercise(guest, stage, evidence, 'b' * 32, DEVICE, 443, sql, request,
            lambda: {'original': 'GUI'}, lambda: True,
            lambda: checks.append('database'), lambda: checks.append('witness'))

    return guest, evidence, checks, exercise


def test_exact_normal_delivery_replay_browser_and_recovery_keep_native_control(case):
    guest, evidence, checks, exercise = case
    result = exercise()
    audit.validate(result)
    assert result['passed'] and all(result[key] for key in audit.FLAGS)
    assert not any(result[key] for key in audit.LIMITS)
    assert guest.calls == ['pending', 'failure', 'restore', 'report', 'pending', 'replay', 'recover', 'report', 'pending']
    assert checks.count('ledger') == 3 and checks.count('Web') == 2 and checks.count('browser') == 1
    assert checks.count('database') == checks.count('witness') == 5
    audit.require_evidence(evidence, {'installed_reconcile_audit': result})
    with pytest.raises(FileExistsError):
        exercise()
    assert guest.calls.count('failure') == 1


@pytest.mark.parametrize('restore_refused', [False, True])
def test_unknown_native_failure_is_never_replayed_and_restore_does_not_mask_it(case, restore_refused):
    guest, evidence, _checks, exercise = case
    original = audit.GuestError('first private failure')
    guest.failure, guest.restore_refused = original, restore_refused
    with pytest.raises(audit.GuestError) as caught:
        exercise()
    assert caught.value is original
    assert guest.calls == ['pending', 'failure', 'restore']
    result = json.loads((evidence / 'installed-reconcile-audit.json').read_text())
    assert not result['passed'] and result['phase'] == 'failure'
    assert result['template_restored'] != restore_refused
    assert 'private' not in json.dumps(result) and 'first' not in json.dumps(result)


def test_control_replacement_after_refusal_is_not_hidden_by_successful_delivery(case):
    guest, evidence, _checks, exercise = case
    original = guest.ssh

    def changed(script, *args, **kwargs):
        value = original(script, *args, **kwargs)
        if ' failure ' in script:
            guest.changed = True
        return value

    guest.ssh = changed
    with pytest.raises(audit.GuestError, match='original native'):
        exercise()
    assert guest.calls == ['pending', 'failure', 'restore']
    result = json.loads((evidence / 'installed-reconcile-audit.json').read_text())
    assert not result['passed'] and result['candidate_refused'] and result['template_restored']


@pytest.mark.parametrize('change', ['numeric_count', 'raw_payload', 'wrong_time', 'wrong_device', 'overflow_action', 'duplicate'])
def test_actual_projection_must_match_original_fields_without_raw_payload(change):
    page = copy.deepcopy(PAGE)
    row = page['items'][0]
    if change == 'numeric_count': row['details']['failure_count'] = 1
    if change == 'raw_payload': row['details']['event_id'] = EVENT['event_id']
    if change == 'wrong_time': row['details']['first_reported_at'] = '2026-11-16T00:00:00.123457Z'
    if change == 'wrong_device': row['target_device_id'] = EVENT['event_id']
    if change == 'overflow_action': row['action'] = 'device.reconcile_overflow'
    if change == 'duplicate': page['items'].append(copy.deepcopy(row))
    with pytest.raises(ValueError):
        audit.projection(page, EVENT, DEVICE)


@pytest.mark.parametrize('change', ['boolean_exit', 'boolean_count', 'wrong_uuid', 'unsafe_time', 'extra_event'])
def test_original_capture_refuses_noncanonical_or_mixed_events(change):
    value = copy.deepcopy(FAILURE)
    if change == 'boolean_exit': value['native_cli_exit'] = True
    if change == 'boolean_count': value['events'][0]['count'] = True
    if change == 'wrong_uuid': value['events'][0]['event_id'] = "private'"
    if change == 'unsafe_time': value['events'][0]['first_at'] = "private'"
    if change == 'extra_event': value['events'].append(copy.deepcopy(EVENT))
    with pytest.raises(ValueError):
        audit.original_event(value, DEVICE)


@pytest.mark.parametrize('change', ['missing_sidecar', 'changed_embedded', 'incomplete', 'missing_browser', 'browser_error', 'missing_image'])
def test_consumer_refuses_incomplete_audit_or_browser_evidence(case, change):
    _guest, evidence, _checks, exercise = case
    value = exercise()
    embedded = copy.deepcopy(value)
    if change == 'missing_sidecar': (evidence / 'installed-reconcile-audit.json').unlink()
    if change == 'changed_embedded': embedded['event_count'] = 0
    if change == 'incomplete':
        embedded['normal_browser_audit_verified'] = False
        (evidence / 'installed-reconcile-audit.json').write_text(json.dumps(embedded))
    if change == 'missing_browser': (evidence / 'installed-reconcile-audit-browser.json').unlink()
    if change == 'browser_error':
        browser = browser_result(); browser['browser_integrity'] = False
        (evidence / 'installed-reconcile-audit-browser.json').write_text(json.dumps(browser))
    if change == 'missing_image': (evidence / 'installed-reconcile-audit.png').unlink()
    with pytest.raises((ValueError, OSError, audit.GuestError)):
        audit.require_evidence(evidence, {'installed_reconcile_audit': embedded})


BUSY = {'available': False, 'reason': 'mutation_busy'}


def busy_clock(monkeypatch):
    clock = {'now': 0.0, 'sleeps': []}
    monkeypatch.setattr(audit.time, 'monotonic', lambda: clock['now'])

    def sleep(seconds):
        clock['sleeps'].append(seconds)
        clock['now'] += seconds

    monkeypatch.setattr(audit.time, 'sleep', sleep)
    return clock


def test_busy_answers_are_retried_and_recorded_only_as_counters(case, monkeypatch):
    guest, evidence, _checks, exercise = case
    clock = busy_clock(monkeypatch)
    ssh, remaining = guest.ssh, {'pending': 2, 'replay': 1}

    def busy_ssh(script, *args, **kwargs):
        if 'configctl' not in script and remaining.get(script.split()[-2]):
            remaining[script.split()[-2]] -= 1
            guest.calls.append('busy')
            clock['now'] += 0.05
            return json.dumps(BUSY).encode()
        return ssh(script, *args, **kwargs)

    guest.ssh = busy_ssh
    result = exercise()
    audit.validate(result)
    assert result['version'] == 2 and result['passed'] and result['mutation_busy_retries'] == 3
    assert result['max_busy_wait_ms'] == 1100 and guest.calls.count('busy') == 3
    assert guest.calls.count('failure') == 1 and clock['sleeps'] == [1] * 3
    audit.require_evidence(evidence, {'installed_reconcile_audit': result})


def test_busy_lock_gives_up_at_the_deadline(case, monkeypatch):
    guest, evidence, _checks, exercise = case
    clock = busy_clock(monkeypatch)
    guest.ssh = lambda *_a, **_k: json.dumps(BUSY).encode()
    with pytest.raises(audit.GuestError, match='lock remained busy'):
        exercise()
    assert clock['now'] >= 100 and clock['now'] < 100.3
    recorded = json.loads((evidence / 'installed-reconcile-audit.json').read_text())
    assert recorded['mutation_busy_retries'] == 101 and recorded['max_busy_wait_ms'] >= 100000
    assert recorded['phase'] == 'baseline' and not recorded['passed']


@pytest.mark.parametrize('other', [{'success': False, 'fixture_phase': 'reconcile_failure_delivery'},
                                   {'available': False, 'reason': 'other'}, {'available': False}])
def test_only_the_exact_busy_answer_is_retried(case, monkeypatch, other):
    guest, _evidence, _checks, exercise = case
    clock = busy_clock(monkeypatch)
    guest.ssh = lambda *_a, **_k: json.dumps(other).encode()
    with pytest.raises(audit.GuestError):
        exercise()
    assert not clock['sleeps']


def evidence_value(version, **extra):
    value = dict.fromkeys(audit.FLAGS + audit.LIMITS, False)
    value.update(version=version, passed=False, phase='baseline', source_head='a' * 40,
                 event_count=0, explicit_normal_reconcile_calls=0)
    value.update(extra)
    return value


def test_validate_accepts_v1_and_v2_and_rejects_bad_counters():
    audit.validate(evidence_value(1))
    audit.validate(evidence_value(2, mutation_busy_retries=0, max_busy_wait_ms=7))
    for bad in [evidence_value(1, mutation_busy_retries=0, max_busy_wait_ms=0),
                evidence_value(2), evidence_value(3, mutation_busy_retries=0, max_busy_wait_ms=0),
                evidence_value(2, mutation_busy_retries=-1, max_busy_wait_ms=0),
                evidence_value(2, mutation_busy_retries=True, max_busy_wait_ms=0),
                evidence_value(2, mutation_busy_retries=0, max_busy_wait_ms=1.5),
                evidence_value(2, mutation_busy_retries=0, max_busy_wait_ms='0')]:
        with pytest.raises(ValueError):
            audit.validate(bad)
