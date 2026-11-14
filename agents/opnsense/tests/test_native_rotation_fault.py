"""Keep disposable response loss confined to one exact edge endpoint."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
from types import ModuleType
from unittest.mock import Mock, patch

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/rotation_recovery.py'
sys.path.insert(0, str(SOURCE.parent))
try:
    SPEC = importlib.util.spec_from_file_location('native_rotation_fault', SOURCE)
    SUITE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(SUITE)
finally:
    sys.path.pop(0)


def test_loss_keeps_native_console_tls_and_other_routes():
    original = (SOURCE.parents[3] / 'deploy/Caddyfile').read_text(encoding='utf-8')
    changed = SUITE.response_loss_config(original)
    start = changed.index('    handle /api/v1/devices/rotate {')
    end = changed.index('    @device path /api/v1/devices/*\n')
    assert changed[:start] + changed[end:] == original
    assert changed[start:end].count('abort') == 1
    assert changed[start:end].count('reverse_proxy nethub-authz:8081') == 1
    assert 'tls' not in changed[start:end]


def test_received_retry_can_remove_only_rotation_endpoint_availability():
    original = (SOURCE.parents[3] / 'deploy/Caddyfile').read_text(encoding='utf-8')
    changed = SUITE.response_loss_config(original, unavailable=True)
    start = changed.index('    handle /api/v1/devices/rotate {')
    end = changed.index('    @device path /api/v1/devices/*\n')
    assert changed[:start] + changed[end:] == original
    assert 'respond 503' in changed[start:end] and 'reverse_proxy' not in changed[start:end]


@pytest.mark.parametrize('configuration', ['', '    @device path /api/v1/devices/*\n' * 2,
    '    @device path /api/v1/devices/*\nhandle_response {}'])
def test_ambiguous_or_previously_faulted_edge_is_refused(configuration):
    with pytest.raises(SUITE.GuestError, match='Unexpected owned edge configuration'):
        SUITE.response_loss_config(configuration)


def test_edge_is_restored_after_interrupted_native_check(tmp_path, monkeypatch):
    path = tmp_path / 'Caddyfile'
    original = (SOURCE.parents[3] / 'deploy/Caddyfile').read_text(encoding='utf-8')
    path.write_text(original, encoding='utf-8')
    reloads = []

    def invoke(arguments, _label):
        if arguments[:2] == ['fixture', 'ps']:
            return b'a' * 64 + b'\n'
        assert arguments[:4] == ['docker', 'exec', 'a' * 64, 'caddy']
        reloads.append(path.read_text(encoding='utf-8'))
        return b''

    monkeypatch.setattr(SUITE, 'invoke', invoke)
    with pytest.raises(RuntimeError, match='Interrupted actual page'):
        with SUITE.owned_edge_fault(tmp_path, ['fixture']):
            assert 'handle_response' in path.read_text(encoding='utf-8')
            raise RuntimeError('Interrupted actual page')
    assert path.read_text(encoding='utf-8') == original
    assert len(reloads) == 2 and reloads[-1] == original


def test_linked_edge_file_is_refused_before_mutation(tmp_path, monkeypatch):
    target = tmp_path / 'unrelated'
    target.write_text('original unrelated content', encoding='utf-8')
    os.link(target, tmp_path / 'Caddyfile')
    monkeypatch.setattr(SUITE, 'invoke', lambda *_: b'a' * 64 + b'\n')
    with pytest.raises(SUITE.GuestError, match='configuration storage changed'):
        with SUITE.owned_edge_fault(tmp_path, ['fixture']):
            pytest.fail('Linked configuration must not be mutated')
    assert target.read_text(encoding='utf-8') == 'original unrelated content'


def readback_guest(result=None, error=None):
    module = ModuleType('rotation')
    calls = []

    class Journal:
        def __init__(self, directory):
            assert directory == '/var/db/nethub-agent'

        def _read(self):
            calls.append('read')
            if error is not None:
                raise error
            return result

    module.RotationJournal = Journal

    def ssh(script, label):
        assert script.startswith('set -eu\ncd /usr/local/opnsense/scripts/nethub-agent\n')
        assert label == 'private prepared native rotation readback'
        code = script.split("<<'PY'\n", 1)[1].removesuffix('PY\n')
        output = io.StringIO()
        with patch.dict(sys.modules, {'rotation': module}), redirect_stdout(output):
            exec(compile(code, '<private-readback>', 'exec'), {})
        return output.getvalue().encode()

    guest = Mock()
    guest.ssh.side_effect = ssh
    return guest, calls


def test_prepared_readback_preserves_the_private_journal_with_one_read():
    pending = {'phase': 'prepared', 'candidate': 'private-candidate', 'native_before': {'private': 'model'}}
    guest, reads = readback_guest(result=pending)
    assert SUITE.prepared_journal(guest) == pending
    guest.ssh.assert_called_once()
    assert reads == ['read']


@pytest.mark.parametrize('error,kind', [
    (FileNotFoundError('private journal path'), 'missing'),
    (PermissionError('private owner path'), 'permission'),
    (ValueError('private invalid value'), 'invalid'),
    (json.JSONDecodeError('private body', 'private document', 0), 'json'),
    (ModuleNotFoundError('private module'), 'missing_module'),
    (RuntimeError('private exception text'), 'other'),
])
def test_prepared_readback_exports_only_original_closed_failure(error, kind):
    guest, reads = readback_guest(error=error)
    with pytest.raises(SUITE.GuestError) as caught:
        SUITE.prepared_journal(guest)
    assert str(caught.value) == 'Private native journal readback failed: read/' + kind
    assert 'private ' not in str(caught.value)
    guest.ssh.assert_called_once()
    assert reads == ['read']


def test_prepared_readback_reports_import_failure_without_reading_a_journal():
    guest = Mock()

    def ssh(script, _label):
        output = io.StringIO()
        code = script.split("<<'PY'\n", 1)[1].removesuffix('PY\n')
        with patch.dict(sys.modules, {'rotation': ModuleType('rotation')}), redirect_stdout(output):
            exec(compile(code, '<private-readback>', 'exec'), {})
        return output.getvalue().encode()

    guest.ssh.side_effect = ssh
    with pytest.raises(SUITE.GuestError, match='Private native journal readback failed: import/import'):
        SUITE.prepared_journal(guest)
    guest.ssh.assert_called_once()


def test_prepared_readback_exposes_only_allowlisted_basename_and_line():
    try:
        exec(compile("raise ValueError('private candidate and journal path')", '/private/location/rotation.py', 'exec'))
    except ValueError as error:
        guest, reads = readback_guest(error=error)
    with pytest.raises(SUITE.GuestError) as caught:
        SUITE.prepared_journal(guest)
    assert str(caught.value) == 'Private native journal readback failed: read/invalid/rotation.py:1'
    assert '/private' not in str(caught.value) and 'candidate' not in str(caught.value)
    guest.ssh.assert_called_once()
    assert reads == ['read']


@pytest.mark.parametrize('change', [
    {'kind': 'private exception text'}, {'kind': []}, {'stage': 'private path'},
    {'locations': [{'source': '/private/rotation.py', 'line': 1}]},
    {'locations': [{'source': 'rotation.py', 'line': True}]},
    {'locations': [{'source': 'rotation.py', 'line': 20001}]},
    {'locations': [{'source': 'rotation.py', 'line': 1, 'private': 'value'}]},
    {'private': 'candidate'}, {'version': True}, {'success': 1},
])
def test_prepared_readback_refuses_untrusted_failure_fields(change):
    value = dict(version=1, success=False, stage='read', kind='invalid', locations=[])
    value.update(change)
    guest = Mock()
    guest.ssh.return_value = json.dumps(value).encode()
    with pytest.raises(SUITE.GuestError, match='Private native journal readback outcome differs'):
        SUITE.prepared_journal(guest)
    guest.ssh.assert_called_once()
