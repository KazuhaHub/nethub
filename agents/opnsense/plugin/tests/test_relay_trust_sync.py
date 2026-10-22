"""Keep application, fetch and retryable server confirmation as distinct phases."""
from unittest import mock

import pytest

from test_relay_trust_transaction import transaction, example
import relay_trust_sync as CLIENT
from protocol import ProtocolError


def sync(transaction):
    value = example()
    return CLIENT.TrustSynchronizer(transaction).sync('https://console.example.com', 'A'*43,
        value['device_id'], value['desired']['server_name'])


def test_fetch_apply_and_confirmation_retry_have_no_second_reload(transaction):
    with mock.patch.object(CLIENT, 'request_json', side_effect=[example(), ProtocolError('private response')]) as network:
        assert sync(transaction)['phase'] == 'applied_unconfirmed'
        assert [call.args[1] for call in network.call_args_list] == [
            '/api/v1/devices/relay-trust/settings', '/api/v1/devices/relay-trust/applied']
    with mock.patch.object(CLIENT, 'request_json', side_effect=[example(), example('relay-trust-applied-response')]):
        assert sync(transaction)['confirmed'] is True
    with mock.patch.object(CLIENT, 'request_json', return_value=example()) as network:
        assert sync(transaction)['confirmed'] is True
        assert network.call_count == 1
    assert transaction.backend.operations == ['install'] and transaction.calls == ['reload']


def test_pending_delivery_cannot_report_application(transaction):
    value = example(); value['desired'] = None
    with mock.patch.object(CLIENT, 'request_json', return_value=value) as network:
        assert sync(transaction) == {'success': True, 'phase': 'pending', 'confirmed': False}
    assert network.call_count == 1 and transaction.backend.operations == []
    assert transaction.read() is None


def test_failed_application_cannot_report_or_clear_recovery(transaction):
    transaction.backend.fault = 'before_write'
    with mock.patch.object(CLIENT, 'request_json', return_value=example()) as network:
        with pytest.raises(CLIENT.TrustSyncError): sync(transaction)
    assert network.call_count == 1 and transaction.read()['phase'] == 'rolled_back'


def test_changed_enrollment_during_https_fetch_refuses_native_write(transaction):
    def fetch(*args, **kwargs):
        transaction.backend.current['binding'] = 'b'*64
        return example()
    with mock.patch.object(CLIENT, 'request_json', side_effect=fetch):
        with pytest.raises(CLIENT.TrustSyncError): sync(transaction)
    assert transaction.backend.operations == [] and transaction.read() is None


def test_bad_fetch_and_empty_desired_cannot_erase_applied_trust(transaction):
    transaction.apply(example())
    for response in [ProtocolError('private remote message'), dict(example(), desired=None), dict(example(), device_id='other')]:
        with mock.patch.object(CLIENT, 'request_json', side_effect=[response] if isinstance(response, Exception) else None,
                               return_value=response):
            with pytest.raises(CLIENT.TrustSyncError): sync(transaction)
    assert transaction.read()['phase'] == 'applied'
    assert transaction.backend.operations == ['install']
