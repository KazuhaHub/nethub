"""Keep native WAN success separate from attempted changes and restored failures."""
import importlib.util
import json
import re
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock

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


@pytest.mark.parametrize('kind', ['guest_ssh_connection_reset', 'command_timeout', 'fixture_wan_probe'])
def test_wan_inspection_retains_original_closed_ssh_kind_without_replay(monkeypatch, tmp_path, kind):
    class FailedGuest(Guest):
        def ssh(self, script, *args, **kwargs):
            if self.actions.count('restore') and self.actions[-1] == 'inspect':
                error = RECOVERY.GuestError('private-error-text-must-not-escape')
                error.ssh_failure_kind = kind
                raise error
            return super().ssh(script, *args, **kwargs)

    guest = FailedGuest()
    with pytest.raises(RECOVERY.GuestError):
        exercise(monkeypatch, tmp_path, guest)
    result = json.loads((tmp_path / 'installed-wan-recovery.json').read_text())
    assert result['version'] == 3 and result['phase'] == 'identity' and not result['passed']
    assert result['failure_ssh_kind'] == kind and result['restore_ssh_kind'] is None
    assert guest.actions.count('change') == guest.actions.count('restore') == 1
    assert 'private' not in json.dumps(result)


@pytest.mark.parametrize('kind', ['private-error-text-must-not-escape', True])
def test_unknown_ssh_attributes_never_enter_wan_evidence(kind):
    error = RECOVERY.GuestError('private-error-text-must-not-escape')
    error.ssh_failure_kind = kind
    assert RECOVERY.ssh_kind(error) is None


def test_original_ssh_failure_is_not_replaced_by_a_restore_failure(monkeypatch, tmp_path):
    class FailedGuest(Guest):
        def ssh(self, script, *args, **kwargs):
            action = script.split()[-2]
            if action in ('change', 'restore'):
                self.actions.append(action)
                error = RECOVERY.GuestError('private-stage-placeholder')
                error.ssh_failure_kind = 'command_timeout' if action == 'change' else 'guest_ssh_connection_refused'
                raise error
            return super().ssh(script, *args, **kwargs)

    guest = FailedGuest()
    with pytest.raises(RECOVERY.GuestError):
        exercise(monkeypatch, tmp_path, guest)
    result = json.loads((tmp_path / 'installed-wan-recovery.json').read_text())
    assert not result['passed'] and result['phase'] == 'change'
    assert result['failure_ssh_kind'] == 'command_timeout'
    assert result['restore_ssh_kind'] == 'guest_ssh_connection_refused'
    assert result['restore_attempted'] and not result['restore_succeeded']
    assert guest.actions.count('change') == guest.actions.count('restore') == 1
    assert 'private' not in json.dumps(result)


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


CONSOLE_FILE = 'installed-wan-identity-console.json'
CONSOLE_VALUES = {'private_sshd_pid_alive': '1', 'sshd_process_count': '3', 'lan_nic_up_running': '1',
                  'lan_address_present': '1', 'pf_enabled': '1', 'pf_rule_lines': '42',
                  'newwanip_last_200_lines': '2', 'linkup_last_200_lines': '0',
                  'filter_reload_last_200_lines': '500000', 'openssh_last_200_lines': '1',
                  'webgui_last_200_lines': '7', 'load_1min_bucket': 'ge4',
                  'nethub_lock_holder_lines': '1', 'second_of_minute': '58'}


def console_output(**changes):
    values = dict(CONSOLE_VALUES, **changes)
    lines = ['console noise', 'NH_WANID_BEGIN'] + ['NHWANID %s=%s\r' % item for item in values.items()]
    return '\r\n'.join(lines + ['NH_WANID_END', 'NH_shell> '])


class FakeConsole:
    def __init__(self, output=None, error=None):
        self.output, self.error, self.scripts = output, error, []

    def command(self, script, timeout=60):
        self.scripts.append((script, timeout))
        if self.error is not None:
            raise self.error
        return self.output


class IdentityGuest(Guest):
    """Fails the first post-restore inspection with the original banner-timeout category."""
    def __init__(self, console=None, fail='identity'):
        super().__init__()
        self.console = console
        self.process = SimpleNamespace(poll=lambda: None)
        self.fail = fail

    def ssh(self, script, *args, **kwargs):
        action = script.split()[-2]
        late = (self.actions.count('restore') and action == 'inspect'
                and self.actions[self.actions.index('restore'):].count('inspect') >= 1)
        if (self.fail == 'identity' and late) or (self.fail == 'change' and action == 'change'):
            error = RECOVERY.GuestError('owned native WAN ' + action + ' failed: guest_ssh_banner_timeout')
            error.ssh_failure_kind = 'guest_ssh_banner_timeout'
            if action == 'change':
                self.address = '10.0.2.16'
            self.actions.append(action)
            raise error
        return super().ssh(script, *args, **kwargs)


def run_identity(monkeypatch, tmp_path, guest):
    with pytest.raises(RECOVERY.GuestError) as caught:
        exercise(monkeypatch, tmp_path, guest)
    assert str(caught.value) == 'Native WAN recovery failed at identity'
    return json.loads((tmp_path / 'installed-wan-recovery.json').read_text())


def test_identity_failure_writes_closed_console_evidence_and_keeps_the_original_failure(monkeypatch, tmp_path):
    console = FakeConsole(console_output())
    guest = IdentityGuest(console)
    result = run_identity(monkeypatch, tmp_path, guest)
    assert result['phase'] == 'identity' and result['failure_reason'] == 'guest_operation'
    assert result['failure_ssh_kind'] == 'guest_ssh_banner_timeout' and result['restore_failure_reason'] is None
    path = tmp_path / CONSOLE_FILE
    assert path.stat().st_mode & 0o777 == 0o600
    value = json.loads(path.read_text())
    sys.modules['wan_identity_console'].validate(value)
    assert value == {'version': 1, 'collected': True, 'collection_failure': None,
                     'private_sshd_pid_alive': True, 'sshd_process_count': 3,
                     'lan_nic_up_running': True, 'lan_address_present': True, 'pf_enabled': True,
                     'pf_rules_present': True, 'newwanip_last_200_lines': 2, 'linkup_last_200_lines': 0,
                     'filter_reload_last_200_lines': 999, 'openssh_last_200_lines': 1,
                     'webgui_last_200_lines': 7, 'load_1min_bucket': '>=4',
                     'nethub_lock_holder_present': True, 'second_of_minute': 58, 'second_near_cron_start': True}
    assert len(console.scripts) == 1 and console.scripts[0][1] == 30
    assert guest.actions.count('change') == guest.actions.count('restore') == 1


@pytest.mark.parametrize('console,failure', [
    (None, 'console_unavailable'),
    (FakeConsole(error=RECOVERY.GuestError('Owned guest serial deadline exceeded: LEAK-SENTINEL')), 'console_error'),
    (FakeConsole(error=RuntimeError('LEAK-SENTINEL')), 'console_error'),
    (FakeConsole('NH_WANID_BEGIN\nLEAK-SENTINEL\nNH_WANID_END\n'), 'invalid_output'),
    (FakeConsole('no markers LEAK-SENTINEL'), 'invalid_output'),
    (FakeConsole(console_output(second_of_minute='60')), 'invalid_output'),
    (FakeConsole(console_output(load_1min_bucket='private')), 'invalid_output'),
])
def test_console_collection_failure_is_closed_and_preserves_the_original_failure(
        monkeypatch, tmp_path, console, failure):
    result = run_identity(monkeypatch, tmp_path, IdentityGuest(console))
    assert result['failure_ssh_kind'] == 'guest_ssh_banner_timeout' and result['phase'] == 'identity'
    raw = (tmp_path / CONSOLE_FILE).read_text()
    assert 'LEAK' not in raw
    value = json.loads(raw)
    sys.modules['wan_identity_console'].validate(value)
    assert value['collected'] is False and value['collection_failure'] == failure


def test_stopped_guest_process_yields_unavailable_console_without_a_command(monkeypatch, tmp_path):
    console = FakeConsole(console_output())
    guest = IdentityGuest(console)
    guest.process = SimpleNamespace(poll=lambda: 1)
    run_identity(monkeypatch, tmp_path, guest)
    assert json.loads((tmp_path / CONSOLE_FILE).read_text())['collection_failure'] == 'console_unavailable'
    assert console.scripts == []


def test_unwritable_console_evidence_never_replaces_the_original_failure(monkeypatch, tmp_path):
    (tmp_path / CONSOLE_FILE).write_bytes(b'earlier attempt\n')
    result = run_identity(monkeypatch, tmp_path, IdentityGuest(FakeConsole(console_output())))
    assert result['failure_ssh_kind'] == 'guest_ssh_banner_timeout'
    assert (tmp_path / CONSOLE_FILE).read_bytes() == b'earlier attempt\n'


def test_console_evidence_is_only_collected_for_the_identity_phase(monkeypatch, tmp_path):
    console = FakeConsole(console_output())
    exercise(monkeypatch, tmp_path, IdentityGuest(console, fail=None))
    assert not (tmp_path / CONSOLE_FILE).exists() and console.scripts == []
    other = tmp_path / 'change'
    other.mkdir()
    with pytest.raises(RECOVERY.GuestError, match='failed at change'):
        exercise(monkeypatch, other, IdentityGuest(console, fail='change'))
    assert not (other / CONSOLE_FILE).exists() and console.scripts == []
    restore = tmp_path / 'restore'
    restore.mkdir()

    class RestoreFails(IdentityGuest):
        def ssh(self, script, *args, **kwargs):
            if script.split()[-2] == 'restore':
                raise RECOVERY.GuestError('owned native WAN restore failed: fixture_wan_route_missing')
            return super().ssh(script, *args, **kwargs)
    with pytest.raises(RECOVERY.GuestError, match='failed at restore'):
        exercise(monkeypatch, restore, RestoreFails(console, fail=None))
    assert not (restore / CONSOLE_FILE).exists() and console.scripts == []


def test_console_evidence_validator_refuses_extra_or_out_of_range_values():
    helper = sys.modules['wan_identity_console']
    good = helper.parse(console_output())
    helper.validate(good)
    for key, bad in [('sshd_process_count', 65), ('sshd_process_count', True),
                     ('newwanip_last_200_lines', 1000), ('linkup_last_200_lines', -1),
                     ('load_1min_bucket', '3'), ('second_of_minute', 60), ('second_of_minute', True),
                     ('second_near_cron_start', False), ('pf_enabled', 1), ('version', 2),
                     ('collection_failure', 'private text'), ('collected', 1)]:
        with pytest.raises(ValueError):
            helper.validate(dict(good, **{key: bad}))
    with pytest.raises(ValueError):
        helper.validate(dict(good, extra='private text'))
    with pytest.raises(ValueError):
        helper.validate({key: item for key, item in good.items() if key != 'pf_enabled'})
    uncollected = helper.uncollected('invalid_output')
    helper.validate(uncollected)
    for changes in ({'pf_enabled': False}, {'collection_failure': 'other'}, {'collection_failure': None}):
        with pytest.raises(ValueError):
            helper.validate(dict(uncollected, **changes))
    with pytest.raises(ValueError):
        helper.validate(dict(good, collection_failure='console_error'))


def test_console_parser_ignores_noise_but_refuses_duplicate_missing_or_malformed_lines():
    helper = sys.modules['wan_identity_console']
    assert helper.parse('NHWANID pf_enabled=0\n' + console_output(pf_enabled='0'))['pf_enabled'] is False
    duplicate = console_output().replace('NH_WANID_END', 'NHWANID pf_enabled=1\r\nNH_WANID_END')
    for bad in (duplicate, console_output().replace('NHWANID pf_enabled=1', 'x'),
                console_output(pf_enabled='2'), console_output(second_of_minute='07'),
                console_output() + console_output(), 'NH_WANID_END\nNH_WANID_BEGIN\n', None):
        with pytest.raises(ValueError):
            helper.parse(bad)
    assert helper.parse(console_output(second_of_minute='7'))['second_near_cron_start'] is False
    assert helper.parse(console_output(second_of_minute='25'))['second_near_cron_start'] is True
    assert helper.parse(console_output(second_of_minute='35'))['second_near_cron_start'] is True


ALLOWED_COMMANDS = {'export', 'printf', 'head', 'kill', 'pgrep', 'wc', 'tr', 'ifconfig', 'sed', 'case', 'grep',
                    'pfctl', 'tail', 'awk', 'sysctl', 'fstat', 'date', 'test', 'true', 'if', 'then', 'else', 'fi',
                    'esac', 'out', 'logs', 'count'}


def script_segments(script):
    text = re.sub(r"'[^']*'", 'Q', script)           # single-quoted data (sed/awk/printf programs)
    text = re.sub(r'\w+\(\)', ' ', text)                # function definitions
    text = re.sub(r'\*,[^)\n]*\)|\*\)', ' ', text)         # case patterns
    text = text.replace('"', ' ').replace(';;', ';')
    return text, [part.split() for part in re.split(r'\$\(|[()|;{}`&\n]+', text)]


def test_console_observation_script_is_read_only():
    script = sys.modules['wan_identity_console'].SCRIPT
    text, segments = script_segments(script)
    commands = set()
    for words in segments:
        while words and words[0] in ('then', 'else', 'if', '!'):
            commands.add(words[0])
            words = words[1:]
        if words and re.fullmatch(r'[A-Za-z_]+=\S*', words[0]):
            words = words[1:]
        if not words:
            continue
        name = words[0].rsplit('/', 1)[-1]
        assert name in ALLOWED_COMMANDS, name
        commands.add(name)
        args = ' '.join(words[1:]).replace('2>/dev/null', '').strip()
        if name == 'kill':
            assert args == '-0 $pid'
        elif name == 'pfctl':
            assert args in ('-si', '-sr')
        elif name == 'sysctl':
            assert args == '-n vm.loadavg'
        elif name == 'ifconfig':
            assert args in ('em0', 'em0 inet')
        assert '-w' not in words[1:]
    assert {'kill', 'pfctl', 'sysctl', 'ifconfig', 'pgrep', 'fstat'} <= commands
    assert not commands & {'tee', 'touch', 'rm', 'mv', 'cp', 'service', 'configctl', 'pluginctl'}
    for redirection in re.finditer(r'\d*>+[^\s;)]*', text):
        assert redirection[0] == '2>/dev/null', redirection[0]
    assert '<<' not in text and '>' not in text.replace('2>/dev/null', '')


def test_console_evidence_is_written_after_the_original_recovery_record(monkeypatch, tmp_path):
    seen = []

    class OrderedConsole(FakeConsole):
        def command(self, script, timeout=60):
            record = tmp_path / 'installed-wan-recovery.json'
            seen.append((record.exists(), record.stat().st_mode & 0o777, json.loads(record.read_text())['phase']))
            return super().command(script, timeout)
    run_identity(monkeypatch, tmp_path, IdentityGuest(OrderedConsole(console_output())))
    assert seen == [(True, 0o600, 'identity')]
    assert (tmp_path / CONSOLE_FILE).exists()


def test_console_observation_restores_the_serial_wait_phase():
    helper = sys.modules['wan_identity_console']

    class PhaseConsole(FakeConsole):
        phase = 'native_inspection'

        def command(self, script, timeout=60):
            self.phase = 'serial_command'
            raise RuntimeError('boom')
    console = PhaseConsole()
    guest = SimpleNamespace(console=console, process=SimpleNamespace(poll=lambda: None))
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        helper.retain(guest, directory)
        assert json.loads((Path(directory) / CONSOLE_FILE).read_text())['collection_failure'] == 'console_error'
    assert console.phase == 'native_inspection'


def test_console_is_skipped_without_guest_activity_when_it_cannot_be_recorded(tmp_path):
    helper = sys.modules['wan_identity_console']
    console = FakeConsole(console_output())
    guest = SimpleNamespace(console=console, process=SimpleNamespace(poll=lambda: None))
    helper.retain(guest, tmp_path / 'missing')
    assert not (tmp_path / 'missing').exists()
    (tmp_path / CONSOLE_FILE).write_bytes(b'earlier\n')
    helper.retain(guest, tmp_path)
    assert console.scripts == [] and (tmp_path / CONSOLE_FILE).read_bytes() == b'earlier\n'
    dangling = tmp_path / 'dangling'
    dangling.mkdir()
    (dangling / CONSOLE_FILE).symlink_to(dangling / 'nowhere')
    helper.retain(guest, dangling)
    assert console.scripts == [] and not (dangling / 'nowhere').exists()


def test_console_write_failure_leaves_no_temporary_or_partial_file(monkeypatch, tmp_path):
    helper = sys.modules['wan_identity_console']
    console = FakeConsole(console_output())
    guest = SimpleNamespace(console=console, process=SimpleNamespace(poll=lambda: None))
    for name in ('fsync', 'link'):
        monkeypatch.setattr(helper.os, name, Mock(side_effect=OSError('disk')))
        helper.retain(guest, tmp_path)
        monkeypatch.undo()
        assert list(tmp_path.iterdir()) == []
    helper.retain(guest, tmp_path)
    assert [item.name for item in tmp_path.iterdir()] == [CONSOLE_FILE]
    assert (tmp_path / CONSOLE_FILE).stat().st_mode & 0o777 == 0o600
