"""Exercise real agent dispatch, controlled reload and lifecycle intent fences."""
import json
from pathlib import Path
from unittest import mock
import xml.etree.ElementTree as ET

import pytest

pytest.importorskip('fcntl')
from test_lifecycle_agent import case
from test_relay_trust_transaction import transaction, example
from relay_trust_transaction import TrustTransactionError
from relay_trust_sync import TrustSyncError


def configure_name(case):
    path = case.root/'conf/config.xml'
    tree = ET.parse(path)
    ET.SubElement(tree.find('OPNsense/NetHubAgent'), 'server_name').text = 'relay.example.com'
    tree.write(path)


def test_agent_dispatch_checks_lifecycle_and_persists_only_public_status(case):
    configure_name(case)
    with mock.patch('relay_trust_sync.TrustSynchronizer.sync', return_value={
        'success': True, 'phase': 'applied', 'generation': 1, 'confirmed': True, 'secret': 'must-not-appear'}) as sync:
        result = case.agent.apply('trust')
    assert result['phase'] == 'applied' and result['confirmed'] is True
    assert sync.call_args.args == ('https://console.example.com', 'A'*43,
                                  '11111111-1111-4111-8111-111111111111', 'relay.example.com')
    assert 'secret' not in result and 'must-not-appear' not in json.dumps(case.agent.status())
    assert case.agent.status()['relay_trust']['phase'] == 'applied'


@pytest.mark.parametrize('marker', ['disabled', 'stopped', 'revoked', 'uninstalling'])
def test_inactive_trust_never_contacts_console_or_starts_service(case, marker):
    configure_name(case)
    case.agent.state.mkdir(parents=True, exist_ok=True)
    (case.agent.state/marker).touch()
    with mock.patch('relay_trust_sync.TrustSynchronizer.sync') as sync:
        assert case.agent.apply('trust')['phase'] == 'inactive'
    sync.assert_not_called()
    assert case.mutations() == [] and (case.agent.state/marker).exists()


def test_failed_trust_action_cannot_suppress_independent_revocation_report(case):
    configure_name(case)
    with mock.patch('relay_trust_sync.TrustSynchronizer.sync', side_effect=TrustSyncError('private')):
        result = case.agent.apply('trust')
    assert result['success'] is False and 'private' not in json.dumps(result)
    with mock.patch('lifecycle.report_health', return_value={'revoked': True}):
        assert case.agent.apply('report')['revoked'] is True
    assert not case.active and (case.agent.state/'revoked').exists()


def test_ordinary_reconcile_restores_pending_trust_before_render(case):
    directory = case.agent.config/'relay-trust'; directory.mkdir(mode=0o700)
    events = []
    pending = mock.Mock()
    def recover(): events.append('recover'); return {'phase': 'rolled_back'}
    pending.recover.side_effect = recover
    original = case.agent.run
    def run(args, **kwargs):
        if str(args[0]) == '/usr/local/sbin/configctl': events.append('render')
        return original(args, **kwargs)
    case.agent.run = run
    with mock.patch.object(case.agent, 'trust_transaction', return_value=pending):
        assert case.agent.apply('reconcile')['success'] is True
    assert events == ['recover', 'render']


def test_failed_pending_recovery_blocks_reconcile_render_and_restart(case):
    directory = case.agent.config/'relay-trust'; directory.mkdir(mode=0o700)
    pending = mock.Mock(); pending.recover.side_effect = TrustTransactionError('private')
    with mock.patch.object(case.agent, 'trust_transaction', return_value=pending):
        result = case.agent.apply('reconcile')
    assert result['success'] is False and 'private' not in json.dumps(result)
    assert not any(call[0] == '/usr/local/sbin/configctl' for call in case.calls)
    assert case.mutations() == []


def test_controlled_reload_override_is_scoped_and_does_not_reenter_recovery(case):
    transaction = case.agent.trust_transaction()
    def reconcile(**kwargs):
        assert kwargs == {'trust_recovery': False}
        case.agent.service('onestart')
        return {'success': True}
    with mock.patch.object(case.agent, 'reconcile_locked', side_effect=reconcile):
        assert transaction.reload() is True
    assert case.calls[-1] == ['/usr/sbin/service', '-E', 'NETHUB_TRUST_APPLY_ONCE=1', 'nethub_agent_frpc', 'onestart']
    case.agent.service('onestart')
    assert case.calls[-1] == ['/usr/sbin/service', 'nethub_agent_frpc', 'onestart']
    with mock.patch.object(case.agent, 'reconcile_locked', side_effect=RuntimeError('fixture')):
        with pytest.raises(RuntimeError): transaction.reload()
    assert case.agent._trust_reload is False


def test_quiesce_confirms_owned_stop_without_changing_operator_intent(case):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    assert case.agent.trust_transaction().quiesce() is True
    assert not case.active
    assert all(not (case.agent.state/name).exists() for name in ('stopped', 'revoked', 'disabled'))
    assert case.mutations() == ['onestop']


def test_unenroll_recovers_trust_before_server_revocation_or_native_clear(case):
    events = []
    def recover(): events.append('recover')
    def remove(*args): events.append('remove'); return {'revoked': True}
    with mock.patch.object(case.agent, 'recover_trust', side_effect=recover), mock.patch('lifecycle.request_removal', side_effect=remove):
        assert case.agent.apply('unenroll')['success'] is True
    assert events == ['recover', 'remove']


def test_failed_trust_recovery_keeps_removal_credentials_for_retry(case):
    original = (case.root/'conf/config.xml').read_bytes()
    directory = case.agent.config/'relay-trust'; directory.mkdir(mode=0o700)
    pending = mock.Mock(); pending.recover.side_effect = TrustTransactionError('fixture')
    with mock.patch.object(case.agent, 'trust_transaction', return_value=pending), mock.patch('lifecycle.request_removal') as network:
        result = case.agent.apply('unenroll')
    assert result['success'] is False
    assert (case.root/'conf/config.xml').read_bytes() == original
    network.assert_not_called()


def test_common_mutation_lock_excludes_trust_action(case):
    import fcntl
    case.agent.state.mkdir(parents=True, exist_ok=True)
    with (case.agent.state/'reconcile.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with mock.patch('relay_trust_sync.TrustSynchronizer.sync') as network:
            assert case.agent.apply('trust')['action'] == 'busy'
            network.assert_not_called()


def test_residual_native_trust_metadata_blocks_forget(case):
    path = case.root/'conf/config.xml'; tree = ET.parse(path)
    model = tree.find('OPNsense/NetHubAgent')
    for key in ('device_id', 'device_secret', 'frp_token', 'domain_claim'):
        model.find(key).text = ''
    model.find('enabled').text = '0'
    ET.SubElement(model, 'relay_trust_state').text = 'retain-for-review'
    tree.write(path)
    with mock.patch.object(case.agent, 'trust_transaction') as transaction:
        assert case.agent.apply('forget')['success'] is False
    transaction.assert_not_called()
