"""Keep native WAN success separate from attempted changes and restored failures."""
import importlib.util
import json
from pathlib import Path
import sys

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


def exercise(monkeypatch, tmp_path, guest):
    monkeypatch.setattr(RECOVERY, 'Guest', Guest)
    return RECOVERY.exercise(guest, tmp_path, 'a' * 32, lambda _name: {'model': 'original'},
        lambda: True, lambda: {'GUI': 'original'}, lambda: None, lambda: None)


def test_success_requires_change_and_restore_without_agent_commands(monkeypatch, tmp_path):
    guest = Guest()
    result = exercise(monkeypatch, tmp_path, guest)
    assert result['passed'] and result['phase'] == 'completed'
    assert guest.actions == ['inspect', 'change', 'inspect', 'restore', 'inspect']
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


def test_private_projection_refuses_unrelated_or_ambiguous_controls():
    value = json.loads(Guest().ssh('inspect nonce'))
    RECOVERY.projection(value)
    for key, bad in [('pid', True), ('pid', 0), ('pid', 2**31), ('started', ''),
                     ('address', '192.0.2.1'), ('runtime_sha256', 'private raw content'),
                     ('control_sources', ['10.0.2.15', '10.0.2.16'])]:
        with pytest.raises(ValueError):
            RECOVERY.projection(dict(value, **{key: bad}))
