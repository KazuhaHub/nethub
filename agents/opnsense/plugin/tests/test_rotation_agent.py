"""Dispatch rotation under the shared lock without exposing private assignments."""
from unittest import mock

import pytest
import test_reconcile as base


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
    with mock.patch.object(case.agent, 'rotation_backend') as backend:
        result = case.agent.apply('rotate')
    assert result['success'] is False and result['action'] == 'rotate'
    backend.assert_not_called()
