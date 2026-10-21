"""Keep certificate scheduling failures separate from tunnel lifecycle state."""
import json
from unittest import mock

import pytest

from test_lifecycle_agent import case
from certificate_sync import CertificateSyncError
from certificate_transaction import CertificateTransactionError


@pytest.mark.parametrize('marker', ['disabled', 'stopped', 'revoked', 'uninstalling'])
def test_inactive_intent_prevents_certificate_network_and_service_changes(case, marker):
    case.agent.state.mkdir(parents=True)
    (case.agent.state / marker).touch()
    with mock.patch('certificate_sync.CertificateSynchronizer.sync') as sync:
        result = case.agent.apply('certificate')
    assert result['phase'] == 'inactive'
    sync.assert_not_called()
    assert case.active and not case.mutations()


def test_disabled_model_skips_certificate_sync(case):
    case.set_enabled(False)
    with mock.patch('certificate_sync.CertificateSynchronizer.sync') as sync:
        assert case.agent.apply('certificate')['phase'] == 'inactive'
    sync.assert_not_called()
    assert case.active and not case.mutations()


def test_certificate_failure_does_not_overwrite_tunnel_health_or_config(case):
    case.agent.state.mkdir(parents=True)
    status = case.agent.state / 'state.json'
    status.write_text('{"success":true,"action":"noop"}\n')
    before = status.read_bytes()
    config = (case.root / 'conf/config.xml').read_bytes()
    live = case.agent.live.read_bytes()
    with mock.patch('certificate_sync.CertificateSynchronizer.sync', side_effect=CertificateSyncError('private upstream output')):
        result = case.agent.apply('certificate')
    assert result['success'] is False and result['phase'] == 'error'
    assert 'private' not in json.dumps(result)
    assert status.read_bytes() == before and case.agent.live.read_bytes() == live
    assert (case.root / 'conf/config.xml').read_bytes() == config
    assert case.active and not case.mutations()
    assert case.agent.status()['gui_certificate']['phase'] == 'error'


def test_certificate_status_exposes_only_fixed_public_fields(case):
    result = {'success': True, 'action': 'certificate', 'phase': 'verified', 'message': 'Verified',
              'generation': 2, 'valid_until': '2027-01-01T00:00:00.000000Z',
              'chain_pem': 'not returned', 'device_secret': 'not returned'}
    with mock.patch('certificate_sync.CertificateSynchronizer.sync', return_value=result), \
            mock.patch.object(case.agent, 'apply_gui_certificate', return_value=result):
        saved = case.agent.apply('certificate')
    assert 'chain_pem' not in saved and 'device_secret' not in saved
    assert case.agent.status()['gui_certificate'] == saved
    assert case.active and not case.mutations()


def test_certificate_action_obeys_the_shared_lock(case):
    import fcntl
    case.agent.state.mkdir(parents=True)
    with (case.agent.state / 'reconcile.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with mock.patch('certificate_sync.CertificateSynchronizer.sync') as sync:
            assert case.agent.apply('certificate')['action'] == 'busy'
    sync.assert_not_called()
    assert case.active and not case.mutations()


def test_pending_recovery_runs_before_disabled_intent_without_new_synchronization(case):
    case.set_enabled(False)
    transaction = mock.Mock()
    with mock.patch.object(case.agent, 'gui_transaction', return_value=transaction), \
            mock.patch('certificate_sync.CertificateSynchronizer.sync') as sync:
        assert case.agent.apply('certificate')['phase'] == 'inactive'
    transaction.recover.assert_called_once_with()
    sync.assert_not_called()
    assert case.active and not case.mutations()


def test_unconfirmed_recovery_prevents_new_download_and_keeps_tunnel_state(case):
    transaction = mock.Mock()
    transaction.recover.side_effect = CertificateTransactionError('GUI certificate application needs local recovery; tunnel configuration was retained')
    with mock.patch.object(case.agent, 'gui_transaction', return_value=transaction), \
            mock.patch('certificate_sync.CertificateSynchronizer.sync') as sync:
        assert case.agent.apply('certificate')['phase'] == 'error'
    sync.assert_not_called()
    assert case.active and not case.mutations()


def test_pending_issuance_never_enters_native_application(case):
    with mock.patch('certificate_sync.CertificateSynchronizer.sync', return_value={
            'success': True, 'action': 'certificate', 'phase': 'pending', 'message': 'Pending'}), \
            mock.patch.object(case.agent, 'apply_gui_certificate') as apply:
        assert case.agent.apply('certificate')['phase'] == 'pending'
    apply.assert_not_called()
    assert case.active and not case.mutations()
