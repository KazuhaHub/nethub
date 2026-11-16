"""Exercise fixture locking/restoration with the real private outbox implementation."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'acceptance'), str(ROOT / 'plugin/src/usr/local/opnsense/scripts/nethub-agent')]
try:
    spec = importlib.util.spec_from_file_location('native_failure_probe_test', ROOT / 'acceptance/reconcile_failure_probe.py')
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    from reconcile_audit import Outbox
finally:
    del sys.path[:2]


DEVICE = '11111111-1111-4111-8111-111111111111'


@pytest.fixture
def case(tmp_path):
    state = tmp_path / 'var/db/nethub-agent'
    state.mkdir(mode=0o700, parents=True)
    (state / 'reconcile.lock').write_bytes(b'')
    (state / 'reconcile.lock').chmod(0o600)
    (tmp_path / 'conf').mkdir()
    (tmp_path / 'conf/config.xml').write_text('<opnsense><OPNsense><NetHubAgent>'
        '<enabled>1</enabled><device_id>' + DEVICE + '</device_id>'
        '<console_url>https://console.example.com</console_url>'
        '<device_secret>unit-test-placeholder</device_secret>'
        '</NetHubAgent></OPNsense></opnsense>')
    owner = tmp_path / 'root/nethub-ci'
    owner.mkdir(mode=0o700, parents=True)
    template = tmp_path / probe.TEMPLATE
    template.parent.mkdir(parents=True)
    original = (ROOT / 'plugin/src' / probe.TEMPLATE).read_bytes()
    template.write_bytes(original)
    template.chmod(0o644)
    source = owner / 'source/agents/opnsense/plugin/src' / probe.TEMPLATE
    source.parent.mkdir(parents=True)
    source.write_bytes(original)
    calls, sent = [], []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        assert argv == ['/usr/local/bin/python3.13',
            str(tmp_path / 'usr/local/opnsense/scripts/nethub-agent/agentctl.py'), '--locked', 'reconcile']
        assert kwargs == {'capture_output': True, 'timeout': 45}
        if template.read_bytes().startswith(probe.BAD_PREFIX):
            Outbox(state, DEVICE).record_failure()
            value = {'success': False, 'action': 'error', 'audit_recorded': True,
                     'message': 'frpc rejected the candidate configuration; live configuration was retained'}
            return SimpleNamespace(returncode=1, stdout=probe.encoded(value), stderr=b'')
        return SimpleNamespace(returncode=0, stdout=probe.encoded({'success': True, 'action': 'unchanged'}), stderr=b'')

    def send(*args):
        sent.append(args)
        return False

    fixture = probe.Fixture(tmp_path, box=Outbox, send=send, runner=runner)
    return SimpleNamespace(root=tmp_path, state=state, original=original, template=template,
        source=source, calls=calls, sent=sent, fixture=fixture, box=Outbox(state, DEVICE))


def test_failure_keeps_the_original_lock_captures_real_outbox_and_restores_bytes(case):
    inode = (case.state / 'reconcile.lock').stat().st_ino
    result = case.fixture.failure()
    assert result['candidate_refused'] and result['template_restored'] and result['native_cli_exit'] == 1
    assert result['device_id'] == DEVICE and len(result['events']) == 1
    assert result['events'] == case.fixture.pending()['events']
    assert case.template.read_bytes() == case.original and case.template.stat().st_mode & 0o777 == 0o644
    assert (case.state / 'reconcile.lock').stat().st_ino == inode
    assert case.fixture.journal()['restored'] is True
    captured = case.fixture.directory / 'captured.json'
    assert captured.stat().st_mode & 0o777 == 0o600 and captured.stat().st_nlink == 1
    assert json.loads(captured.read_text()) == {'device_id': DEVICE, 'events': result['events']}
    assert 'unit-test-placeholder' not in json.dumps(result) and len(case.calls) == 1


def test_existing_failure_is_never_rearmed_or_silently_discarded(case):
    original = case.fixture.failure()
    with pytest.raises((FileExistsError, ValueError)):
        case.fixture.failure()
    assert len(case.calls) == 1 and case.fixture.pending()['events'] == original['events']
    assert case.template.read_bytes() == case.original


def test_interrupted_arm_restores_the_original_template_without_starting_cli(case):
    atomic = case.fixture.atomic
    original = ValueError('private-arm-error')

    def interrupted(path, raw, mode=0o600):
        atomic(path, raw, mode)
        if path == case.template and raw.startswith(probe.BAD_PREFIX):
            raise original

    case.fixture.atomic = interrupted
    with pytest.raises(ValueError) as caught:
        case.fixture.failure()
    assert caught.value is original
    assert case.template.read_bytes() == case.original and case.fixture.journal()['restored']
    assert not case.calls and not case.fixture.pending()['events']


def test_replay_and_recovery_require_actual_ack_then_keep_original_payload(case):
    original = case.fixture.failure()['events']
    with pytest.raises(ValueError):
        case.fixture.replay()
    with pytest.raises(ValueError):
        case.fixture.recover()
    assert not case.sent and len(case.calls) == 1
    case.box.acknowledge([e['event_id'] for e in original])
    assert case.fixture.replay() == {'replayed': True, 'event_count': 1}
    assert case.sent == [('https://console.example.com', 'unit-test-placeholder', DEVICE, original)]
    with pytest.raises(FileExistsError):
        case.fixture.replay()
    assert len(case.sent) == 1
    assert case.fixture.pending()['events'] == []
    assert case.fixture.recover() == {'recovered_without_restart': True, 'native_cli_exit': 0}
    with pytest.raises(FileExistsError):
        case.fixture.recover()
    assert len(case.calls) == 2


@pytest.mark.parametrize('outcome', ['storage_failure', 'unexpected_success', 'timeout'])
def test_failed_or_uncertain_child_stays_failed_with_original_template(case, outcome):
    def runner(*_args, **_kwargs):
        if outcome == 'timeout':
            raise subprocess.TimeoutExpired('private-command-placeholder', 45)
        result = {'success': outcome == 'unexpected_success', 'audit_recorded': False, 'action': 'error'}
        return SimpleNamespace(returncode=0, stdout=probe.encoded(result), stderr=b'private-child-placeholder')

    case.fixture.run = runner
    with pytest.raises((ValueError, subprocess.TimeoutExpired)):
        case.fixture.failure()
    assert case.template.read_bytes() == case.original and case.fixture.journal()['restored']
    assert not (case.fixture.directory / 'captured.json').exists()


def test_restore_refuses_unrelated_template_changes_without_overwriting_them(case):
    case.fixture.failure()
    case.template.write_bytes(b'unrelated local edit\n')
    with pytest.raises(ValueError):
        case.fixture.restore()
    assert case.template.read_bytes() == b'unrelated local edit\n'


@pytest.mark.parametrize('kind', ['source_mismatch', 'symlink', 'hardlink', 'writable'])
def test_unadmitted_or_unsafe_templates_cannot_start_a_fixture(case, kind):
    if kind == 'source_mismatch':
        case.source.write_bytes(b'different source\n')
    elif kind == 'symlink':
        case.template.unlink()
        case.template.symlink_to(case.source)
    elif kind == 'hardlink':
        case.template.unlink()
        os.link(case.source, case.template)
    else:
        case.template.chmod(0o666)
    with pytest.raises((OSError, ValueError)):
        case.fixture.failure()
    assert not case.calls and not case.fixture.directory.exists()


def test_cli_boundary_failure_never_constructs_a_mutation_fixture(monkeypatch, capsys):
    def refuse(_nonce, **_kwargs):
        raise ValueError('private-boundary-placeholder')

    monkeypatch.setattr(probe, 'boundary', refuse)
    monkeypatch.setattr(probe, 'Fixture', lambda: pytest.fail('Boundary must precede construction'))
    assert probe.main(['failure', 'a' * 32]) == 1
    result = capsys.readouterr()
    assert json.loads(result.out) == {'success': False, 'fixture_phase': 'reconcile_failure_fixture'}
    assert 'private-boundary-placeholder' not in result.out
