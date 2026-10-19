"""Validate health-only payloads and authenticated lifecycle acknowledgements."""
import copy
import json
from pathlib import Path
import sys
import shutil
import subprocess
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'agents/opnsense/plugin/src/usr/local/opnsense/scripts/nethub-agent'))
import lifecycle
from protocol import ProtocolError

STATUS = json.loads((ROOT / 'proto/examples/valid/status-response.json').read_text())
ID = STATUS['device_id']


def test_payload_is_health_only_and_normalizes_microsecond_utc():
    report = lifecycle.health_request(ID, '26.7.7', '0.0.4', 'running', {
        'success': False, 'updated_at': '2026-10-18T00:00:00+00:00',
        'message': 'private local diagnostic', 'credentials': 'must not be sent'})
    assert set(report) == {'agent_protocol_version', 'device_id', 'platform_version', 'agent_version',
                           'service_state', 'last_reconcile_success', 'last_reconcile_at'}
    assert report['last_reconcile_at'] == '2026-10-18T00:00:00.000000Z'
    assert report['last_reconcile_success'] is False
    assert 'private' not in json.dumps(report) and 'credentials' not in json.dumps(report)


@pytest.mark.parametrize('record', [None, [], {'success': 'yes'}, {'success': True, 'updated_at': 'invalid'}, {'success': True}])
def test_invalid_local_reconcile_metadata_is_not_transmitted(record):
    report = lifecycle.health_request(ID, '', '', 'disabled', record)
    assert report['last_reconcile_success'] is None and report['last_reconcile_at'] is None


@pytest.mark.parametrize('change', [dict(device_id='another'),dict(revoked='true'),dict(accepted=False),dict(accepted=1),dict(agent_protocol_version='2.0.0'),dict(agent_protocol_version='1.00.0')])
def test_untrusted_acknowledgement_cannot_change_local_state(change):
    response = copy.deepcopy(STATUS);response.update(change)
    with pytest.raises(ProtocolError, match='^Invalid device acknowledgement$'):
        lifecycle.acknowledgement(response, ID, 'status')


def test_only_confirmed_revocation_is_accepted_and_optional_extensions_ignored():
    response = {key: value for key, value in STATUS.items() if key != 'accepted'}
    response.update(revoked=True, future={'ignored': True})
    assert lifecycle.acknowledgement(response, ID, 'unenroll')['revoked'] is True
    assert 'future' not in lifecycle.acknowledgement(response, ID, 'unenroll')
    response['revoked'] = False
    with pytest.raises(ProtocolError):
        lifecycle.acknowledgement(response, ID, 'unenroll')


def test_network_helpers_use_fixed_paths_and_bearer_not_body():
    response = dict(STATUS, revoked=True)
    with mock.patch.object(lifecycle, 'request_json', return_value=response) as network:
        lifecycle.request_removal('https://console.example.com', 'A' * 43, ID)
    args, kwargs = network.call_args
    assert args[1] == '/api/v1/devices/unenroll' and args[2] == lifecycle.identity(ID)
    assert kwargs['secret'] == 'A' * 43 and 'A' * 43 not in json.dumps(args[2])


@pytest.mark.skipif(shutil.which('php') is None, reason='Requires target PHP or Linux CI')
def test_removal_controller_confirm_then_clear_under_native_lock(tmp_path):
    directory = tmp_path / 'requests';directory.mkdir(mode=0o700)
    plugin = ROOT / 'agents/opnsense/plugin'
    controller = plugin / 'src/usr/local/opnsense/mvc/app/controllers/OPNsense/NetHubAgent/Api/RemoveController.php'
    result = subprocess.run(['php', str(plugin / 'tests/removal_controller_contract.php'), str(controller), str(directory)], text=True, capture_output=True, check=True)
    assert json.loads(result.stdout)['removal_cases_passed'] == ['success', 'empty', 'unconfirmed', 'wrong-id', 'model-invalid', 'changed-model', 'cleanup-failed', 'get-only', 'readonly', 'busy']
    assert not result.stderr
