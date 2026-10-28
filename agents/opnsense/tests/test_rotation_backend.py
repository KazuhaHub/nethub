"""Verify bounded private subprocess transport and preserved model policy."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'agents/opnsense/plugin/src/usr/local/opnsense/scripts/nethub-agent'))
from rotation import RotationError
from rotation_backend import NativeRotationBackend, assignment, replacement
from protocol import VERSION


@pytest.fixture
def nodes():
    value = json.loads((ROOT / 'proto/examples/valid/enroll-response.json').read_text(encoding='utf-8'))
    fields = ('device_id', 'device_secret', 'frp_token', 'server_addr', 'server_name', 'subdomain', 'domain_claim')
    result = {key: value[key] for key in fields}
    result.update(console_url='https://console.example.com', server_port=str(value['server_port']),
                  relay_ca=base64.b64encode(value['relay_ca_pem'].encode()).decode(), enabled='0', relay_trust_state='')
    return result


def test_private_native_read_uses_stdin_without_credentials_in_arguments(nodes):
    run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps({'success': True, 'result': {'nodes': nodes}}).encode(), b''))
    with mock.patch.object(os, 'geteuid', return_value=0, create=True):
        assert NativeRotationBackend(run=run).read() == nodes
    args, kwargs = run.call_args
    assert len(args[0]) == 2 and args[0][0] == '/usr/local/bin/php'
    assert nodes['device_secret'] not in str(args)
    assert json.loads(kwargs['input']) == {'action': 'read', 'request': []}
    assert kwargs['timeout'] == 5 and kwargs['capture_output'] is True


def test_model_assignment_conversion_retains_policy_and_trust(nodes):
    value = assignment(nodes)
    assert value['agent_protocol_version'] == VERSION
    value['device_secret'] = 'B' * 42 + 'A'
    result = replacement(nodes, value)
    assert result['enabled'] == '0' and result['relay_trust_state'] == ''
    assert result['relay_ca'] == nodes['relay_ca'] and result['console_url'] == nodes['console_url']


@pytest.mark.parametrize('reply', [
    {'success': False, 'message': 'private fixture diagnostic'},
    {'success': 1, 'result': {}}, {'success': True, 'result': {}},
    {'success': True, 'result': {'nodes': []}},
])
def test_bad_subprocess_reply_has_only_a_fixed_error(reply):
    run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(reply).encode(), b''))
    with mock.patch.object(os, 'geteuid', return_value=0, create=True):
        with pytest.raises(RotationError, match='^Native rotation model operation failed$'):
            NativeRotationBackend(run=run).read()


def test_nonroot_native_call_never_spawns_child():
    run = mock.Mock()
    with mock.patch.object(os, 'geteuid', return_value=1000, create=True):
        with pytest.raises(RotationError):
            NativeRotationBackend(run=run).read()
    run.assert_not_called()
