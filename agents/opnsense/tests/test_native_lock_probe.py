"""Keep lock evidence bounded and distinguish holders from mere open files."""
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


SPEC = importlib.util.spec_from_file_location('native_lock_probe_test',
    Path(__file__).resolve().parents[1] / 'acceptance/native_lock_probe.py')
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def table(*rows):
    return (' '.join(PROBE.HEADER) + '\n' + '\n'.join(rows)).encode()


def test_only_exact_held_regular_lock_descriptors_are_selected():
    raw = table(
        '71 python3.13 3 v r rw-----l 1 0 - ' + PROBE.LOCK_PATH,
        '72 python3.13 3 v r rw------ 1 0 - ' + PROBE.LOCK_PATH,
        '73 private-command 3 v r rw-----l 1 0 - /private-not-the-lock',
        '71 python3.13 4 v r rw-----l 1 0 - ' + PROBE.LOCK_PATH)
    assert PROBE.held_descriptors(raw) == [71, 71]
    with pytest.raises(ValueError):
        PROBE.held_descriptors(b'private-output-not-a-table')
    with pytest.raises(ValueError):
        PROBE.held_descriptors(table('71 x 3 v r private-flags 1 0 - ' + PROBE.LOCK_PATH))


@pytest.mark.parametrize(('command', 'expected'), [
    ('/usr/local/bin/python3.13 ' + PROBE.SCRIPT_PATH + 'agentctl.py --locked trust', 'agent_trust'),
    ('/usr/local/bin/python3.13 ' + PROBE.SCRIPT_PATH + 'agentctl.py rotate', 'agent_rotate'),
    ('/usr/local/bin/python3.13 ' + PROBE.SCRIPT_PATH + 'watchdog.py', 'agent_watchdog'),
    ('/usr/bin/lockf -sk -t 0 private-file private-command', 'lock_wrapper'),
    ('/untrusted/python ' + PROBE.SCRIPT_PATH + 'agentctl.py rotate', 'other'),
    ('/usr/local/bin/python3.13 ' + PROBE.SCRIPT_PATH + 'agentctl.py rotate private-secret', 'other'),
    ('private-secret "', 'other'),
])
def test_process_arguments_project_only_fixed_roles(command, expected):
    assert PROBE.role(command.encode()) == expected


def test_snapshot_deduplicates_processes_and_never_exports_arguments(monkeypatch):
    monkeypatch.setattr(PROBE.sys, 'platform', 'freebsd15')
    calls = []
    def read(arguments, deadline, limit):
        calls.append(arguments)
        if arguments[0].endswith('procstat'):
            return 'complete', table(*[
                f'71 python3.13 {fd} v r rw-----l 1 0 - {PROBE.LOCK_PATH}' for fd in (3, 4)])
        return 'complete', b'/private-command private-secret'
    monkeypatch.setattr(PROBE, 'read_command', read)
    value = PROBE.inspect()
    PROBE.validate(value)
    assert value['held_descriptor_count'] == 2 and value['holder_roles'] == ['other']
    assert len(calls) == 2 and value['arguments_complete'] is True
    assert 'private' not in json.dumps(value) and '71' not in json.dumps(value)


def test_partial_or_unavailable_observation_is_not_an_unlocked_claim(monkeypatch):
    monkeypatch.setattr(PROBE.sys, 'platform', 'freebsd15')
    monkeypatch.setattr(PROBE, 'read_command', lambda *args: ('timeout', b''))
    value = PROBE.inspect()
    PROBE.validate(value)
    assert value['status'] == 'timeout' and value['arguments_complete'] is False
    assert value['original_failure_cause_established'] is False
    value['holder_roles'] = ['private-secret']
    with pytest.raises(ValueError):
        PROBE.validate(value)


def test_process_sampling_is_capped_without_claiming_complete_arguments(monkeypatch):
    monkeypatch.setattr(PROBE.sys, 'platform', 'freebsd15')
    calls = []
    def read(arguments, deadline, limit):
        calls.append(arguments)
        if arguments[0].endswith('procstat'):
            return 'complete', table(*[
                f'{pid} python3.13 3 v r rw-----l 1 0 - {PROBE.LOCK_PATH}'
                for pid in range(71, 77)])
        return 'complete', b'/usr/local/bin/python3.13 private-script private-secret'
    monkeypatch.setattr(PROBE, 'read_command', read)
    value = PROBE.inspect()
    PROBE.validate(value)
    assert len(calls) == 5 and value['held_descriptor_count'] == 6
    assert value['arguments_complete'] is False and value['holder_roles'] == ['other']
    assert 'private' not in json.dumps(value)


def test_oversized_or_non_utf8_descriptor_table_is_not_accepted():
    with pytest.raises(ValueError):
        PROBE.held_descriptors(table(*[
            f'71 python3.13 {fd} v r rw-----l 1 0 - {PROBE.LOCK_PATH}' for fd in range(65)]))
    with pytest.raises(UnicodeError):
        PROBE.held_descriptors(b'\xff')


@pytest.mark.parametrize('failure', ['oversize', 'nonzero', 'timeout', 'launch'])
def test_command_output_and_exceptions_never_escape(monkeypatch, failure):
    def run(arguments, **kwargs):
        if failure == 'timeout':
            raise subprocess.TimeoutExpired(arguments, 1, output=b'private-secret')
        if failure == 'launch':
            raise OSError('private-secret')
        kwargs['stdout'].write(b'private-secret' * 4)
        return subprocess.CompletedProcess(arguments, 1 if failure == 'nonzero' else 0)
    monkeypatch.setattr(PROBE.subprocess, 'run', run)
    status, raw = PROBE.read_command(['private-command'], PROBE.time.monotonic() + 2, 8)
    assert status in ('oversize', 'unavailable', 'timeout') and raw == b''
