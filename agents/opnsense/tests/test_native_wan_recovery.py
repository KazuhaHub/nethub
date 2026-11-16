"""Keep native WAN success separate from attempted changes and restored failures."""
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/wan_recovery.py'
sys.path.insert(0, str(SOURCE.parent))
try:
    SPEC = importlib.util.spec_from_file_location('native_wan_recovery_test', SOURCE)
    RECOVERY = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(RECOVERY)
finally:
    sys.path.pop(0)


class Guest:
    def __init__(self, *, lost_change=False):
        self.address = '10.0.2.15'
        self.actions = []
        self.lost_change = lost_change

    def put(self, *_args):
        pass

    def ssh(self, script, *_args, **_kwargs):
        action = script.split()[-2]
        self.actions.append(action)
        if action == 'change':
            self.address = '10.0.2.16'
            if self.lost_change:
                raise RECOVERY.GuestError('Simulated result loss')
        if action == 'restore':
            self.address = '10.0.2.15'
            return json.dumps({'restored': True})
        return json.dumps({'address': self.address, 'pid': 123, 'started': 'original process',
                           'control_sources': [self.address], 'runtime_sha256': 'a' * 64,
                           'native_xml_sha256': 'b' * 64})


@pytest.fixture(autouse=True)
def fake_clock(monkeypatch):
    class Clock:
        stamp = 0.0

        def sleep(self, seconds):
            self.stamp += seconds

    clock = Clock()
    monkeypatch.setattr(RECOVERY.time, 'monotonic', lambda: clock.stamp)
    monkeypatch.setattr(RECOVERY.time, 'sleep', clock.sleep)
    return clock


def exercise(monkeypatch, tmp_path, guest):
    monkeypatch.setattr(RECOVERY, 'Guest', Guest)
    return RECOVERY.exercise(guest, tmp_path, 'a' * 32, lambda _name: {'model': 'original'},
        lambda: True, lambda: {'GUI': 'original'}, lambda: None, lambda: None)


def test_success_requires_change_and_restore_without_agent_commands(monkeypatch, tmp_path):
    guest = Guest()
    result = exercise(monkeypatch, tmp_path, guest)
    assert result['passed'] and result['phase'] == 'completed'
    assert guest.actions[:5] == ['inspect', 'change', 'inspect', 'restore', 'inspect']
    assert guest.actions[5:] and set(guest.actions[5:]) == {'inspect'}
    settling = json.loads((tmp_path / 'installed-wan-settling.json').read_text())
    assert settling['passed'] and settling['stable_ms'] >= 15000
    assert settling['read_only_observation'] and not settling['network_or_package_operation_replayed']
    assert all(result[key] is True for key in RECOVERY.FLAGS)
    assert all(result[key] is False for key in RECOVERY.LIMITS)
    for key, value in [('passed', False), ('restore_attempted', False), ('change_ms', None),
                       ('change_ms', 60001), ('version', True), ('same_frpc_process', False),
                       ('manual_agent_start_or_reconcile', True)]:
        with pytest.raises(ValueError):
            RECOVERY.validate(dict(result, **{key: value}))


def test_lost_change_response_restores_but_does_not_turn_failure_into_success(monkeypatch, tmp_path):
    guest = Guest(lost_change=True)
    with pytest.raises(RECOVERY.GuestError, match='failed at change'):
        exercise(monkeypatch, tmp_path, guest)
    result = json.loads((tmp_path / 'installed-wan-recovery.json').read_text())
    assert result['passed'] is False and result['phase'] == 'change'
    assert result['restore_attempted'] and result['restore_succeeded']
    assert guest.address == '10.0.2.15'
    assert guest.actions.count('change') == guest.actions.count('restore') == 1
    assert result['change_ms'] is None
    assert result['failure_reason'] == 'guest_operation'
    assert result['restore_failure_reason'] is None


def test_late_route_gap_delays_readiness_without_replaying_or_changing_first_recovery_time(
        monkeypatch, tmp_path, fake_clock):
    class LateGapGuest(Guest):
        def ssh(self, script, *args, **kwargs):
            if self.actions.count('restore') and 7.5 <= fake_clock.stamp < 9.5:
                assert script.split()[-2] == 'inspect'
                self.actions.append('inspect')
                raise RECOVERY.GuestError('owned native WAN inspect failed: fixture_wan_route_missing')
            return super().ssh(script, *args, **kwargs)

    guest = LateGapGuest()
    result = exercise(monkeypatch, tmp_path, guest)
    settling = json.loads((tmp_path / 'installed-wan-settling.json').read_text())
    assert result['passed'] and result['restore_ms'] == 1
    assert settling['passed'] and settling['missing_route_samples'] > 0
    assert 24500 <= settling['elapsed_ms'] <= 60000 and settling['stable_ms'] >= 15000
    assert guest.actions.count('change') == guest.actions.count('restore') == 1


def test_persistent_late_missing_route_stays_failed_at_the_original_deadline(
        monkeypatch, tmp_path, fake_clock):
    class MissingGuest(Guest):
        def ssh(self, script, *args, **kwargs):
            if self.actions.count('restore') and fake_clock.stamp >= 5:
                assert script.split()[-2] == 'inspect'
                self.actions.append('inspect')
                raise RECOVERY.GuestError('owned native WAN inspect failed: fixture_wan_route_missing')
            return super().ssh(script, *args, **kwargs)

    guest = MissingGuest()
    with pytest.raises(RECOVERY.GuestError, match='failed at identity'):
        exercise(monkeypatch, tmp_path, guest)
    result = json.loads((tmp_path / 'installed-wan-recovery.json').read_text())
    settling = json.loads((tmp_path / 'installed-wan-settling.json').read_text())
    assert not result['passed'] and result['restore_ms'] == 1
    assert not settling['passed'] and settling['phase'] == 'deadline'
    assert settling['missing_route_samples'] > 0
    assert guest.actions.count('change') == guest.actions.count('restore') == 1


@pytest.mark.parametrize('kind', ['process', 'control', 'route'])
def test_witness_change_retains_fixed_reason_and_never_replays_WAN(monkeypatch, tmp_path, kind):
    guest = Guest()
    monkeypatch.setattr(RECOVERY, 'Guest', Guest)

    def witness():
        if guest.actions.count('restore') and guest.actions[-1] == 'inspect':
            RECOVERY.require_witness(SimpleNamespace(poll=lambda: 1 if kind == 'process' else None),
                {'original-private-socket'}, lambda: set() if kind == 'control' else {'original-private-socket'},
                lambda: kind != 'route')

    with pytest.raises(RECOVERY.GuestError, match='failed at identity'):
        RECOVERY.exercise(guest, tmp_path, 'a' * 32, lambda _name: {'original': 'model'},
            lambda: True, lambda: {'original': 'GUI'}, witness, lambda: None)
    result = json.loads((tmp_path / 'installed-wan-recovery.json').read_text())
    assert result['failure_reason'] == {'process': 'witness_process_changed',
        'control': 'witness_control_changed', 'route': 'witness_route_unavailable'}[kind]
    assert result['restore_succeeded'] and not result['passed']
    assert guest.actions.count('change') == guest.actions.count('restore') == 1
    assert 'private' not in json.dumps(result)


def test_retained_witness_checks_original_process_control_and_route_once():
    calls = []
    def checked(name, value):
        calls.append(name)
        return value
    RECOVERY.require_witness(SimpleNamespace(poll=lambda: checked('process', None)),
        {'original'}, lambda: checked('control', {'original'}), lambda: checked('route', True))
    assert calls == ['process', 'control', 'route']


@pytest.mark.parametrize('reason', ['wan_route_mismatch', 'wan_route_table', 'wan_probe'])
def test_settling_never_retries_wrong_routes_or_unclassified_failures(
        monkeypatch, tmp_path, fake_clock, reason):
    class WrongGuest(Guest):
        def ssh(self, script, *args, **kwargs):
            if self.actions.count('restore') and fake_clock.stamp >= 1:
                self.actions.append('inspect')
                raise RECOVERY.GuestError('owned native WAN inspect failed: fixture_' + reason)
            return super().ssh(script, *args, **kwargs)

    guest = WrongGuest()
    with pytest.raises(RECOVERY.GuestError, match='failed at identity'):
        exercise(monkeypatch, tmp_path, guest)
    settling = json.loads((tmp_path / 'installed-wan-settling.json').read_text())
    assert not settling['passed'] and settling['phase'] == 'observation'
    assert fake_clock.stamp < 2
    assert guest.actions.count('change') == guest.actions.count('restore') == 1


def test_settling_receipt_refuses_unmeasured_or_broader_success(monkeypatch, tmp_path):
    exercise(monkeypatch, tmp_path, Guest())
    helper = sys.modules['wan_settling']
    value = json.loads((tmp_path / 'installed-wan-settling.json').read_text())
    helper.validate(value)
    for key, bad in [('stable_ms', 14999), ('elapsed_ms', 60001), ('samples', True),
                     ('window_max_gap_ms', 1001), ('required_stable_ms', 1),
                     ('read_only_observation', False), ('network_or_package_operation_replayed', True),
                     ('public_or_release_accepted', True), ('phase', 'private raw error')]:
        with pytest.raises(ValueError):
            helper.validate(dict(value, **{key: bad}))


@pytest.mark.parametrize('delay,phase', [(-1, 'clock'), (1.5, 'deadline')])
def test_slow_or_regressed_observations_never_create_a_stable_window(
        tmp_path, fake_clock, delay, phase):
    def observe():
        fake_clock.stamp += delay
        return 'ready'

    with pytest.raises(RECOVERY.GuestError):
        RECOVERY.settle(tmp_path, 0, observe)
    value = json.loads((tmp_path / 'installed-wan-settling.json').read_text())
    assert not value['passed'] and value['phase'] == phase and value['stable_ms'] == 0


def test_existing_settling_record_does_not_authorize_another_attempt(tmp_path):
    path = tmp_path / 'installed-wan-settling.json'
    path.write_bytes(b'original retained outcome\n')

    def refuse():
        pytest.fail('An existing attempt must not invoke the observer')

    with pytest.raises(FileExistsError):
        RECOVERY.settle(tmp_path, 0, refuse)
    assert path.read_bytes() == b'original retained outcome\n'


def test_late_success_is_a_failure_even_when_the_route_is_available(monkeypatch, tmp_path):
    stamp = iter(range(0, 1000, 61))
    monkeypatch.setattr(RECOVERY.time, 'monotonic', lambda: next(stamp))
    guest = Guest()
    with pytest.raises(RECOVERY.GuestError, match='failed at change'):
        exercise(monkeypatch, tmp_path, guest)
    result = json.loads((tmp_path / 'installed-wan-recovery.json').read_text())
    assert result['passed'] is False and result['change_ms'] is None
    assert result['restore_attempted'] and guest.address == '10.0.2.15'
    assert guest.actions.count('change') == guest.actions.count('restore') == 1
    assert result['failure_reason'] == result['restore_failure_reason'] == 'deadline'


def test_closed_probe_reason_survives_restore_failure_without_raw_output(monkeypatch, tmp_path):
    class FailedGuest(Guest):
        def ssh(self, script, *args, **kwargs):
            action = script.split()[-2]
            if action == 'change':
                raise RECOVERY.GuestError('owned native WAN change failed: fixture_wan_route_mismatch')
            if action == 'restore':
                raise RECOVERY.GuestError('owned native WAN restore failed: fixture_wan_route_missing')
            return super().ssh(script, *args, **kwargs)
    with pytest.raises(RECOVERY.GuestError, match='failed at change'):
        exercise(monkeypatch, tmp_path, FailedGuest())
    result = json.loads((tmp_path / 'installed-wan-recovery.json').read_text())
    assert result['failure_reason'] == 'wan_route_mismatch'
    assert result['restore_failure_reason'] == 'wan_route_missing'
    assert result['restore_attempted'] and not result['restore_succeeded']
    assert not result['passed']
    for changes in ({'failure_reason': None}, {'failure_reason': 'raw private child output'},
                    {'restore_attempted': False}, {'restore_succeeded': True}):
        with pytest.raises(ValueError):
            RECOVERY.validate(dict(result, **changes))


def test_private_projection_refuses_unrelated_or_ambiguous_controls():
    value = json.loads(Guest().ssh('inspect nonce'))
    RECOVERY.projection(value)
    for key, bad in [('pid', True), ('pid', 0), ('pid', 2**31), ('started', ''),
                     ('address', '192.0.2.1'), ('runtime_sha256', 'private raw content'),
                     ('control_sources', ['10.0.2.15', '10.0.2.16'])]:
        with pytest.raises(ValueError):
            RECOVERY.projection(dict(value, **{key: bad}))


@pytest.mark.parametrize('field,value,reason', [
    ('pid', 456, 'process_changed'), ('started', 'new process', 'process_changed'),
    ('runtime_sha256', 'c' * 64, 'runtime_changed'),
    ('native_xml_sha256', 'c' * 64, 'native_xml_changed'),
])
def test_route_recovery_cannot_hide_process_or_configuration_changes(monkeypatch, tmp_path, field, value, reason):
    class ChangedGuest(Guest):
        def ssh(self, script, *args, **kwargs):
            result = json.loads(super().ssh(script, *args, **kwargs))
            if self.address == '10.0.2.16':
                result[field] = value
            return json.dumps(result)
    guest = ChangedGuest()
    with pytest.raises(RECOVERY.GuestError, match='failed at change'):
        exercise(monkeypatch, tmp_path, guest)
    result = json.loads((tmp_path / 'installed-wan-recovery.json').read_text())
    assert not result['passed'] and result['failure_reason'] == reason
    assert result['restore_succeeded'] and result['restore_failure_reason'] is None
    assert guest.actions.count('change') == guest.actions.count('restore') == 1
