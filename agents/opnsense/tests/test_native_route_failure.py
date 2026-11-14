"""Keep failed route evidence useful without exporting credentials or retrying."""
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest


DIRECTORY = Path(__file__).resolve().parents[1] / 'acceptance'
sys.path.insert(0, str(DIRECTORY))
import route_failure
from native_model_probe import ROUTE_FLAGS, route_conditions, validate_route_conditions
from guest import GuestError


def conditions():
    value = dict.fromkeys(ROUTE_FLAGS, False)
    value.update(reconcile_success=True, reconcile_action='restart', events=['login_failure'])
    return value


def test_real_local_files_project_mismatched_runtime_and_fixed_log_events(tmp_path):
    private = 'private-value-must-not-escape'
    files = {
        'conf/config.xml': '<opnsense><OPNsense><NetHubAgent><enabled>1</enabled>'
            '<domain_claim>new-claim</domain_claim><frp_token>' + private + '</frp_token>'
            '</NetHubAgent></OPNsense></opnsense>',
        'usr/local/etc/nethub-agent/frpc.toml': '[auth]\ntoken="' + private + '"\n'
            '[metadatas]\ndomain_claim="old-claim"\n',
        'var/db/nethub-agent/state.json': json.dumps({'success': True, 'action': 'restart', 'message': private}),
        'var/log/nethub-agent/frpc.log': private + '\nlogin to the server failed: ' + private
            + '\nstart proxy success: ' + private + '\n',
    }
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
    (tmp_path / 'var/db/nethub-agent/stopped').touch()
    runner = Mock(return_value=subprocess.CompletedProcess([], 0))
    result = route_conditions(tmp_path, runner)
    assert result['service_running'] and result['operator_stopped'] and result['model_enabled']
    assert result['runtime_token_matches_model'] and not result['runtime_claim_matches_model']
    assert result['events'] == ['login_failure', 'proxy_success']
    assert private not in json.dumps(result) and 'new-claim' not in json.dumps(result)
    runner.assert_called_once_with(['/usr/sbin/service', 'nethub_agent_frpc', 'onestatus'],
                                   capture_output=True, timeout=5)


@pytest.mark.parametrize('change', [
    {'events': ['private-value-must-not-escape']}, {'events': ['login_failure'] * 11},
    {'service_running': 1}, {'reconcile_success': 'private-value-must-not-escape'},
    {'reconcile_action': 'private-value-must-not-escape'}, {'private_path': '/root/private'},
])
def test_native_projection_rejects_dynamic_or_ambiguous_fields(change):
    with pytest.raises(ValueError, match='Unexpected native route conditions'):
        validate_route_conditions(dict(conditions(), **change))


def test_diagnostic_transport_failure_is_recorded_without_retry_or_child_output(tmp_path):
    guest = Mock()
    guest.ssh.side_effect = GuestError('private-value-must-not-escape')
    observations = {'native': {'curl_exit': 28, 'http_status': 'unavailable', 'verified': False},
                    'unrelated-secret': 'private-value-must-not-escape'}
    route_failure.retain(guest, tmp_path, observations)
    result = json.loads((tmp_path / 'installed-route-failure.json').read_text())
    assert result['native_probe_failure'] == 'guest_operation' and result['native'] is None
    assert result['routes'] == {'native': observations['native']}
    assert 'private-value-must-not-escape' not in json.dumps(result)
    guest.ssh.assert_called_once()
    with pytest.raises(FileExistsError):
        route_failure.retain(guest, tmp_path, {})


def test_malicious_probe_fields_are_never_published(tmp_path):
    guest = Mock()
    guest.ssh.return_value = json.dumps(dict(conditions(), secret='private-value-must-not-escape')).encode()
    route_failure.retain(guest, tmp_path, {'native': {'curl_exit': True, 'http_status': 200, 'verified': False}})
    result = json.loads((tmp_path / 'installed-route-failure.json').read_text())
    assert result['native_probe_failure'] == 'invalid_projection' and result['native'] is None
    assert result['routes'] == {} and 'private-value-must-not-escape' not in json.dumps(result)


def test_closed_success_retains_only_the_existing_observation(tmp_path):
    guest = Mock()
    guest.ssh.return_value = json.dumps(conditions()).encode()
    route_failure.retain(guest, tmp_path, {'native': {'curl_exit': 22, 'http_status': 503, 'verified': False}})
    result = json.loads((tmp_path / 'installed-route-failure.json').read_text())
    assert result['native'] == conditions() and result['native_probe_failure'] is None
    assert result['routes']['native']['http_status'] == 503
    guest.ssh.assert_called_once_with('/usr/local/bin/python3.13 /root/nethub-ci/native_model_probe.py route\n',
        'read-only post-rotation route conditions', timeout=12)
