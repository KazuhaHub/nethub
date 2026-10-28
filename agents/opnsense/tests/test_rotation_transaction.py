"""Recover model-save and reconcile interruptions without another rotation."""
import copy
from unittest import mock

import pytest

from test_rotation_backend import nodes
from test_rotation_journal import response, journal
from rotation import RotationError
from rotation_backend import assignment
from rotation_transaction import rotate


class Model:
    def __init__(self, nodes):
        self.nodes = copy.deepcopy(nodes)
        self.saves = 0
        self.fail_after_save = False

    def read(self):
        return copy.deepcopy(self.nodes)

    def install(self, before, after):
        if self.nodes not in (before, after):
            raise RotationError('synthetic model conflict')
        if self.nodes != after:
            self.saves += 1
            self.nodes = copy.deepcopy(after)
        if self.fail_after_save:
            raise RotationError('synthetic lost save response')


def network_for(original, journal, calls):
    def network(origin, path, body, **kwargs):
        saved = journal._read()
        assert saved['native_before'] is not None
        assert saved['phase'] == 'prepared'
        calls.append(body['operation_id'])
        return response(original, body['operation_id'], body['replacement_secret'])
    return network


def test_lost_model_save_response_recovers_without_second_network_or_save(nodes, journal):
    model = Model(nodes)
    model.fail_after_save = True
    calls = []
    reconcile = mock.Mock(return_value={'success': True})
    with pytest.raises(RotationError):
        rotate(journal, model, reconcile, transport=network_for(assignment(nodes), journal, calls))
    assert model.saves == 1 and journal._read()['phase'] == 'received'
    reconcile.assert_not_called()
    model.fail_after_save = False
    def no_network(*args, **kwargs):
        pytest.fail('received rotation contacted the server again')
    result = rotate(journal, model, reconcile, transport=no_network)
    assert result['success'] and model.saves == 1 and len(calls) == 1
    reconcile.assert_called_once_with()
    assert model.nodes['enabled'] == '0' and not journal.path.exists()
    assert 'device_secret' not in str(result)


def test_failed_reconcile_keeps_received_journal_until_retry(nodes, journal):
    model = Model(nodes)
    reconcile = mock.Mock(side_effect=[{'success': False}, {'success': True}])
    calls = []
    network = network_for(assignment(nodes), journal, calls)
    first = rotate(journal, model, reconcile, transport=network)
    assert first['phase'] == 'saved' and not first['success'] and journal.path.exists()
    assert rotate(journal, model, reconcile, transport=network)['success']
    assert model.saves == 1 and len(calls) == 1 and reconcile.call_count == 2


@pytest.mark.parametrize('field,value', [('enabled', '1'), ('relay_trust_state', 'changed'), ('console_url', 'https://other.example.com')])
def test_changed_policy_or_trust_refuses_pending_operation_before_network(nodes, journal, field, value):
    model = Model(nodes)
    journal.prepare(nodes['console_url'], assignment(nodes), native_before=nodes)
    before = journal.path.read_bytes()
    model.nodes[field] = value
    network, reconcile = mock.Mock(), mock.Mock()
    with pytest.raises(RotationError):
        rotate(journal, model, reconcile, transport=network)
    network.assert_not_called()
    reconcile.assert_not_called()
    assert journal.path.read_bytes() == before and model.saves == 0
