"""Keep failure observations private, bounded and unable to accept the scenario."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

DIRECTORY = Path(__file__).resolve().parents[1] / 'acceptance'
sys.path.insert(0, str(DIRECTORY))
try:
    SPEC = importlib.util.spec_from_file_location('post_wan_failure_test', DIRECTORY / 'post_wan_failure.py')
    DIAG = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(DIAG)
    from package_probe import HASHES, MARKERS
finally:
    sys.path.pop(0)


def snapshot():
    value = {k: 'a' * 64 for k in HASHES}
    value.update(version=1, package_version='0.0.19', profile=[1, 3], markers={k: False for k in MARKERS},
                 running=True, pid=123, process_sha256='b' * 64, control_sha256='c' * 64)
    return value


def test_retained_observations_never_contain_private_values(tmp_path, monkeypatch):
    calls = []
    def read(script):
        calls.append(script)
        return json.dumps(snapshot())
    def run(args, **options):
        calls.append(args)
        assert args[0] == 'curl' and args[-1] == 'https://console.example.com/'
        assert '--data' not in args and '-H' not in args and '-b' not in args and '-k' not in args
        assert options['timeout'] == 12 and '--max-time' in args
        assert options['stderr'] == DIAG.subprocess.DEVNULL
        return SimpleNamespace(returncode=0, stdout=b'200')
    monkeypatch.setattr(DIAG.subprocess, 'run', run)
    value = DIAG.retain(SimpleNamespace(ssh_read_only_inspection=read), Path('/tmp/nethub-unit-stage'),
                        12345, tmp_path, 'd' * 32, 'e' * 40)
    DIAG.validate(value)
    assert len(calls) == 2 and calls[0] == '/usr/local/bin/python3.13 /root/nethub-ci/package_probe.py ' + 'd' * 32 + '\n'
    assert value['guest'] == {'kind': 'verified', 'client_running': True, 'control_present': True}
    assert value['host']['verified'] is True and value['failure_overridden'] is False
    path = tmp_path / 'post-wan-console-failure.json'
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text()) == value
    assert 'a' * 64 not in path.read_text() and 'b' * 64 not in path.read_text() and 'd' * 32 not in path.read_text()


@pytest.mark.parametrize('code', ['fixture_native_package_boundary_route', 'guest_ssh_connect_timeout', 'private-secret'])
def test_only_allowlisted_guest_failure_kind_is_retained(code):
    calls = []
    def read(script):
        calls.append(script)
        raise DIAG.GuestError('native package snapshot failed: ' + code)
    value = DIAG.observe_guest(SimpleNamespace(ssh_read_only_inspection=read), 'd' * 32)
    assert len(calls) == 1
    assert value == {'kind': code if code != 'private-secret' else 'unclassified',
                     'client_running': None, 'control_present': None}


@pytest.mark.parametrize('diagnostic_raises', [False, True])
def test_original_refusal_survives_successful_or_failed_diagnostics(diagnostic_raises, monkeypatch, tmp_path):
    def retain(*_args):
        if diagnostic_raises:
            raise RuntimeError('private-diagnostic-exception')
        return {'host': {'verified': True}}
    monkeypatch.setattr(DIAG, 'retain', retain)
    probe = {'passed': False, 'phase': 'tls', 'failure': 'tls_timeout', 'http_status': 0,
             'verify_code': 0, 'default_CA_file_available': False, 'default_CA_directory_available': True}
    with pytest.raises(DIAG.GuestError, match='^Guest console after WAN probe failed at tls: tls_timeout$'):
        DIAG.refuse(probe, None, None, None, tmp_path, 'd' * 32, 'e' * 40)


@pytest.mark.parametrize('changed', [
    {'failure_overridden': True}, {'diagnostic_only': False}, {'extra': 'private-secret'},
    {'guest': {'kind': 'private-secret', 'client_running': None, 'control_present': None}},
    {'host': {'curl_exit': 0, 'http_status': 500, 'verified': True}}])
def test_unexpected_projection_cannot_be_published(changed):
    value = {'version': 1, 'source_head': 'e' * 40, 'diagnostic_only': True, 'failure_overridden': False,
             'elapsed_ms': 1, 'guest': {'kind': 'unclassified', 'client_running': None, 'control_present': None},
             'host': {'curl_exit': 7, 'http_status': 0, 'verified': False}}
    value.update(copy.deepcopy(changed))
    with pytest.raises(ValueError):
        DIAG.validate(value)
