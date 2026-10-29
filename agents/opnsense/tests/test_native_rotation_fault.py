"""Keep disposable response loss confined to one exact edge endpoint."""
import importlib.util
import os
from pathlib import Path
import sys

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
