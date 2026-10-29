"""Exercise lifecycle stop/ack/clear boundaries without editing native XML."""
import json
from pathlib import Path
import subprocess
from unittest import mock
import xml.etree.ElementTree as ET

import pytest
import test_reconcile as base
from protocol import ProtocolError


@pytest.fixture
def case():
    fixture = base.ReconcileTests()
    fixture.setUp()
    try:
        tree = ET.parse(fixture.root / 'conf/config.xml')
        model = tree.find('OPNsense/NetHubAgent')
        for key, value in {'device_id': '11111111-1111-4111-8111-111111111111', 'device_secret': 'A' * 43,
                           'console_url': 'https://console.example.com', 'frp_token': 'f' * 64, 'domain_claim': 'fixture.claim'}.items():
            ET.SubElement(model, key).text = value
        tree.write(fixture.root / 'conf/config.xml')
        product = fixture.root / 'usr/local/opnsense/version/nethub-agent'
        product.parent.mkdir(parents=True)
        product.write_text(json.dumps({'product_version': '0.0.4'}))
        old = fixture.agent.run
        def command(args, **kwargs):
            if str(args[0]) == '/usr/local/sbin/opnsense-version':
                return subprocess.CompletedProcess(args, 0, '26.7.7', '')
            return old(args, **kwargs)
        fixture.agent.run = command
        yield fixture
    finally:
        fixture.doCleanups()


def test_removal_after_unknown_rotation_commit_uses_saved_candidate(case):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    (case.agent.state / 'rotation.json').write_text('private journal fixture')
    candidate = 'B' * 42 + 'A'
    with mock.patch('rotation.RotationJournal') as journal, \
            mock.patch('lifecycle.request_removal', side_effect=[ProtocolError('old bearer rejected'), {}]) as request:
        journal.return_value.removal_candidate.return_value = candidate
        result = case.agent.apply('unenroll')
    assert result['success'] and result['revoked'] and not case.active
    assert request.call_count == 2 and request.call_args_list[1].args[1] == candidate
    journal.return_value.removal_candidate.assert_called_once_with(
        'https://console.example.com', '11111111-1111-4111-8111-111111111111', 'A' * 43)
    assert (case.agent.state / 'rotation.json').exists()
    assert json.loads((case.agent.state / 'unenroll-confirmed.json').read_text()) == {
        'device_id': '11111111-1111-4111-8111-111111111111', 'revoked': True}


def test_removal_stops_before_network_and_retains_retry_credentials(case):
    original = (case.root / 'conf/config.xml').read_bytes()
    def fail(*args):
        assert not case.active and (case.agent.state / 'revoked').exists()
        raise ProtocolError('private network response must not be returned')
    with mock.patch('lifecycle.request_removal', side_effect=fail):
        result = case.agent.apply('unenroll')
    assert result['success'] is False and 'unconfirmed' in result['message']
    assert 'private' not in json.dumps(result)
    assert (case.root / 'conf/config.xml').read_bytes() == original
    assert case.agent.apply('reconcile')['action'] == 'stop' and not case.active


def test_confirmed_removal_does_not_write_model_or_erase_before_php(case):
    original = (case.root / 'conf/config.xml').read_bytes()
    with mock.patch('lifecycle.request_removal', return_value={'revoked': True}):
        result = case.agent.apply('unenroll')
    assert result['success'] and result['revoked'] and not case.active
    assert json.loads((case.agent.state / 'unenroll-confirmed.json').read_text())['device_id'] == result['device_id']
    assert (case.root / 'conf/config.xml').read_bytes() == original and case.agent.live.exists()
    assert not case.agent.apply('forget')['success']


def test_forget_requires_cleared_model_and_erases_live_backup_trust(case):
    case.set_enabled(False)
    case.agent.state.mkdir(parents=True)
    case.agent.backup.write_text('former credential')
    (case.agent.state / 'recovery.json').write_text('{}')
    result = case.agent.apply('forget')
    assert result['success'] and not case.active
    assert not any(path.exists() for path in (case.agent.live, case.agent.backup, case.agent.config / 'relay-ca.pem', case.agent.state / 'recovery.json', case.agent.state / 'revoked'))
    assert case.agent.apply('reconcile')['action'] == 'stop'


def test_report_sends_only_health_and_leaves_reconcile_receipt_unchanged(case):
    case.agent.state.mkdir(parents=True)
    record = {'success': True, 'updated_at': '2026-10-18T00:00:00+00:00', 'message': 'not transmitted'}
    state = case.agent.state / 'state.json';state.write_text(json.dumps(record))
    original = state.read_bytes()
    with mock.patch('lifecycle.report_health', return_value={'revoked': False}) as network:
        assert case.agent.apply('report')['success']
    assert state.read_bytes() == original
    body = network.call_args.args[2]
    assert body['service_state'] == 'running' and body['last_reconcile_success'] is True
    assert 'not transmitted' not in json.dumps(body)
    assert 'device_secret' not in body and 'domain_claim' not in body and 'frp_token' not in body
    assert case.agent.status()['last_report']['success'] is True


def test_authenticated_revocation_report_fences_service_and_watchdog(case):
    with mock.patch('lifecycle.report_health', return_value={'revoked': True}):
        assert case.agent.apply('report')['revoked']
    assert not case.active and (case.agent.state / 'revoked').exists()
    assert case.agent.apply('start')['action'] == 'stop' and not case.active


def test_legacy_local_settings_without_console_origin_do_not_report(case):
    tree = ET.parse(case.root / 'conf/config.xml')
    tree.find('OPNsense/NetHubAgent/console_url').text = ''
    tree.write(case.root / 'conf/config.xml')
    with mock.patch('lifecycle.report_health') as network:
        assert case.agent.apply('report')['success']
    network.assert_not_called()
    assert not (case.agent.state / 'health.json').exists() and case.active


@pytest.mark.parametrize('action', ['report', 'unenroll', 'forget'])
def test_lifecycle_obeys_shared_mutation_lock(case, action):
    import fcntl
    case.agent.state.mkdir(parents=True)
    with (case.agent.state / 'reconcile.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert case.agent.apply(action)['action'] == 'busy'
    assert case.active
