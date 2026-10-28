"""Dispatch rotation under the shared lock without exposing private assignments."""
from unittest import mock
import xml.etree.ElementTree as ET

import pytest
import test_reconcile as base
from test_lifecycle_agent import case as enrolled_case


@pytest.fixture
def case():
    value = base.ReconcileTests()
    value.setUp()
    try:
        yield value
    finally:
        value.doCleanups()


def test_rotation_dispatch_uses_private_journal_and_existing_reconcile(case):
    expected = {'success': True, 'action': 'rotate', 'phase': 'applied', 'message': 'Credentials rotated'}
    backend = object()
    with mock.patch.object(case.agent, 'rotation_backend', return_value=backend), \
            mock.patch('rotation_transaction.rotate', return_value=expected) as operation:
        assert case.agent.apply('rotate') == expected
    journal, actual_backend, reconcile = operation.call_args.args
    assert journal.path == case.agent.state / 'rotation.json'
    assert actual_backend is backend and reconcile == case.agent.reconcile_locked
    assert not (case.agent.state / 'rotation.json').exists()


@pytest.mark.parametrize('marker', ['revoked', 'uninstalling'])
def test_rotation_never_contacts_backend_after_local_removal_or_revocation(case, marker):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    (case.agent.state / marker).touch()
    with mock.patch.object(case.agent, 'rotation_backend') as backend, \
            mock.patch('relay_trust_sync.TrustSynchronizer.sync') as sync:
        result = case.agent.apply('rotate')
    assert result['success'] is False and result['action'] == 'rotate'
    backend.assert_not_called()
    sync.assert_not_called()


@pytest.mark.parametrize('marker', ['disabled', 'stopped'])
def test_explicit_rotation_refreshes_trust_without_releasing_stop_policy(enrolled_case, marker):
    agent = enrolled_case.agent
    configuration = enrolled_case.root / 'conf/config.xml'
    tree = ET.parse(configuration)
    tree.find('OPNsense/NetHubAgent/enabled').text = '0'
    tree.write(configuration)
    before = configuration.read_bytes()
    agent.state.mkdir(parents=True, exist_ok=True)
    (agent.state / marker).touch()
    applied = {'success': True, 'phase': 'applied', 'confirmed': True}
    rotated = {'success': True, 'action': 'rotate', 'phase': 'applied'}
    with mock.patch('relay_trust_sync.TrustSynchronizer.sync', return_value=applied) as sync, \
            mock.patch.object(agent, 'rotation_backend'), \
            mock.patch('rotation_transaction.rotate', return_value=rotated) as rotate:
        assert agent.apply('trust')['phase'] == 'inactive'
        sync.assert_not_called()
        assert agent.apply('rotate') == rotated
    sync.assert_called_once()
    rotate.assert_called_once()
    assert configuration.read_bytes() == before and (agent.state / marker).exists()


@pytest.mark.parametrize('phase', ['prepared', 'received'])
def test_pending_rotation_defers_trust_cron_before_native_or_network_changes(case, phase):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    (case.agent.state / 'rotation.json').write_text('private retained journal')
    with mock.patch('rotation.RotationJournal.pending_phase', return_value=phase) as pending, \
            mock.patch.object(case.agent, 'recover_trust') as recovery, \
            mock.patch.object(case.agent, 'trust_transaction') as transaction:
        result = case.agent.apply('trust')
    assert result['success'] is True and result['phase'] == 'rotation_pending'
    assert result['confirmed'] is False and phase not in result['message']
    pending.assert_called_once_with()
    recovery.assert_not_called()
    transaction.assert_not_called()


def test_invalid_pending_rotation_blocks_trust_cron_before_changes(case):
    from rotation import RotationError
    case.agent.state.mkdir(parents=True, exist_ok=True)
    (case.agent.state / 'rotation.json').write_text('invalid journal')
    with mock.patch('rotation.RotationJournal.pending_phase', side_effect=RotationError('private diagnostic')), \
            mock.patch.object(case.agent, 'recover_trust') as recovery:
        result = case.agent.apply('trust')
    assert result['success'] is False and 'private diagnostic' not in str(result)
    recovery.assert_not_called()
