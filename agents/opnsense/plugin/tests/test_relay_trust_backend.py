"""Check the fixed private model subprocess boundary without native config access."""
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src/usr/local/opnsense/scripts/nethub-agent'))
from relay_trust_backend import NativeTrustBackend, NativeTrustError, model_nodes, model_snapshot
from protocol import VERSION


@pytest.fixture
def message():
    path = Path(__file__).resolve().parents[4]/'proto/examples/valid/relay-trust-settings-response.json'
    return json.loads(path.read_text())


def response(value, code=0, stderr=b''):
    return subprocess.CompletedProcess([], code, json.dumps(value).encode(), stderr)


def test_bounded_native_read_sends_only_public_stdin(message):
    current = {'binding': 'a'*64, 'device_id': message['device_id'], 'server_name': 'relay.example.com', 'nodes': model_nodes(message)}
    run = mock.Mock(return_value=response({'success': True, 'result': current}))
    with mock.patch.object(os, 'geteuid', return_value=0, create=True):
        result = NativeTrustBackend(run=run).read()
    assert result == current
    args, kwargs = run.call_args
    assert args[0] == ['/usr/local/bin/php', str(Path(__file__).resolve().parents[1]/'src/usr/local/opnsense/scripts/nethub-agent/relay_trust_model.php')]
    assert json.loads(kwargs['input']) == {'action': 'read', 'request': []}
    assert kwargs['timeout'] == 5 and kwargs['capture_output'] is True


@pytest.mark.parametrize('peer_version', ['1.5.0', VERSION])
def test_public_model_encoding_round_trip_and_duplicate_metadata_refusal(message, peer_version):
    import base64
    message['agent_protocol_version'] = peer_version
    nodes = model_nodes(message)
    assert model_snapshot(message['device_id'], nodes) == dict(message, agent_protocol_version=VERSION)
    raw = base64.b64decode(nodes['relay_trust_state'])
    nodes['relay_trust_state'] = base64.b64encode(raw.replace(b'{', b'{"generation":1,', 1)).decode()
    with pytest.raises(ValueError): model_snapshot(message['device_id'], nodes)


@pytest.mark.parametrize('reply', [{'success': False, 'message': 'private native diagnostic'},
    {'success': 1, 'result': {}}, {'success': True, 'result': {}, 'other': True},
    {'success': True, 'result': []}, {'success': True, 'result': {'binding': 'secret'}}])
def test_bad_native_response_has_only_a_fixed_error(reply):
    run = mock.Mock(return_value=response(reply))
    with mock.patch.object(os, 'geteuid', return_value=0, create=True):
        with pytest.raises(NativeTrustError, match='^Native relay trust operation failed$'):
            NativeTrustBackend(run=run).read()


@pytest.mark.parametrize('result', [subprocess.CompletedProcess([], 1, b'private child output', b''),
    subprocess.CompletedProcess([], 0, b'x'*65537, b''), subprocess.CompletedProcess([], 0, b'{}', b'x'*8193),
    subprocess.CompletedProcess([], 0, b'{"success":true,"success":false,"result":{}}', b'')])
def test_exit_limits_and_duplicate_reply_members_cannot_pass(result):
    with mock.patch.object(os, 'geteuid', return_value=0, create=True):
        with pytest.raises(NativeTrustError): NativeTrustBackend(run=mock.Mock(return_value=result)).read()


@pytest.mark.parametrize('error', [OSError('private failure'), subprocess.TimeoutExpired('php', 5)])
def test_model_subprocess_failure_does_not_leak_diagnostics(error):
    with mock.patch.object(os, 'geteuid', return_value=0, create=True):
        with pytest.raises(NativeTrustError, match='^Native relay trust operation failed$'):
            NativeTrustBackend(run=mock.Mock(side_effect=error)).read()


def test_unprivileged_model_call_never_spawns_a_child():
    run = mock.Mock()
    with mock.patch.object(os, 'geteuid', return_value=1000, create=True):
        with pytest.raises(NativeTrustError): NativeTrustBackend(run=run).read()
    run.assert_not_called()
