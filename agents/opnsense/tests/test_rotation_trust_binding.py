"""Keep an applied trust generation and receipt bound across credential rotation."""
import copy
import hashlib
from unittest import mock

import pytest

from test_rotation_backend import nodes
from certificate_key import KeyStore
from relay_trust_transaction import TrustTransaction, TrustTransactionError

FIELDS = ('console_url', 'device_id', 'device_secret', 'domain_claim', 'frp_token',
          'server_addr', 'server_name', 'server_port', 'subdomain')


def bind(nodes):
    return hashlib.sha256(KeyStore._encoded({key: nodes[key] for key in FIELDS})).hexdigest()


def fixture(nodes):
    before = dict(nodes, relay_trust_state='opaque-public-trust-metadata')
    after = dict(before, device_secret='B' * 42 + 'A', domain_claim='synthetic-verified-new-claim')
    public = {key: after[key] for key in ('relay_ca', 'relay_trust_state')}
    value = {'binding': bind(before), 'phase': 'applied', 'after': public,
             'receipt': {'generation': 7}, 'snapshot': {'preserved': True}}
    transaction = object.__new__(TrustTransaction)
    transaction.read = mock.Mock(return_value=value)
    transaction.backend = mock.Mock()
    transaction.backend.read.return_value = {'binding': bind(after), 'device_id': after['device_id'],
                                             'server_name': after['server_name'], 'nodes': public}
    transaction._write = mock.Mock()
    return transaction, value, before, after


def test_applied_trust_rebind_preserves_original_generation_and_receipt(nodes):
    transaction, value, before, after = fixture(nodes)
    unchanged = copy.deepcopy(value)
    transaction.rebind_rotation(before, after)
    expected = dict(value, binding=bind(after))
    transaction._write.assert_called_once_with(expected)
    assert value == unchanged
    transaction.read.return_value = expected
    transaction._write.reset_mock()
    transaction.rebind_rotation(before, after)
    transaction._write.assert_not_called()


def test_new_rotation_requires_completed_current_trust(nodes):
    transaction, value, before, after = fixture(nodes)
    transaction._current = mock.Mock(return_value=True)
    transaction.check_rotation_ready()
    value['phase'] = 'rolled_back'
    with pytest.raises(TrustTransactionError):
        transaction.check_rotation_ready()
    value['phase'] = 'applied'
    transaction._current.return_value = False
    with pytest.raises(TrustTransactionError):
        transaction.check_rotation_ready()


@pytest.mark.parametrize('kind', ['pending', 'different_binding', 'unsaved_model', 'changed_ca', 'changed_device'])
def test_unrelated_or_unconfirmed_trust_cannot_be_rebound(nodes, kind):
    transaction, value, before, after = fixture(nodes)
    if kind == 'pending':
        value['phase'] = 'written'
    elif kind == 'different_binding':
        value['binding'] = 'c' * 64
    elif kind == 'unsaved_model':
        transaction.backend.read.return_value['binding'] = bind(before)
    elif kind == 'changed_ca':
        after['relay_ca'] = 'changed'
    else:
        after['device_id'] = '44444444-4444-4444-8444-444444444444'
    with pytest.raises(TrustTransactionError):
        transaction.rebind_rotation(before, after)
    transaction._write.assert_not_called()
