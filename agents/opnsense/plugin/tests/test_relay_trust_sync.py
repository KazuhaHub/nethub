"""Keep application, fetch and retryable server confirmation as distinct phases."""
from unittest import mock

import pytest

from test_relay_trust_transaction import transaction, example
import relay_trust_sync as CLIENT
from protocol import ProtocolError
from relay_trust_backend import NativeTrustError


def test_native_read_failure_is_closed_before_network_or_trust_mutation(transaction):
    with mock.patch.object(transaction.backend, 'read', side_effect=NativeTrustError('private backend details')), \
            mock.patch.object(CLIENT, 'request_json') as network:
        with pytest.raises(CLIENT.TrustSyncError) as failure:
            sync(transaction)
    assert str(failure.value) == 'Relay trust synchronization failed; inspect local trust and recovery status'
    assert failure.value.diagnostic() == {'version': 1, 'stage': 'native_snapshot', 'kind': 'native'}
    network.assert_not_called()
    assert transaction.read() is None
    assert transaction.backend.operations == [] and transaction.calls == []


@pytest.mark.parametrize('stage,kind', [('recover', 'transaction'), ('history', 'storage'),
    ('request', 'protocol'), ('verify', 'value'), ('apply', 'transaction')])
def test_failure_stage_is_retained_without_private_text_or_mutation_replay(transaction, stage, kind):
    from contextlib import ExitStack
    from relay_trust_transaction import TrustTransactionError
    error = {'transaction': TrustTransactionError, 'storage': OSError,
             'protocol': ProtocolError, 'value': ValueError}[kind]('private response and credential must not escape')
    with ExitStack() as stack:
        recover = stack.enter_context(mock.patch.object(transaction, 'recover', return_value=None))
        history = stack.enter_context(mock.patch.object(transaction, 'read', return_value=None))
        request = stack.enter_context(mock.patch.object(CLIENT, 'request_json', return_value=example()))
        verify = stack.enter_context(mock.patch.object(CLIENT, 'verify_settings', return_value=example()))
        apply = stack.enter_context(mock.patch.object(transaction, 'apply'))
        {'recover': recover, 'history': history, 'request': request, 'verify': verify, 'apply': apply}[stage].side_effect = error
        with pytest.raises(CLIENT.TrustSyncError) as failure:
            sync(transaction)
    assert failure.value.diagnostic() == {'version': 1, 'stage': stage, 'kind': kind}
    assert 'private' not in str(failure.value) and 'credential' not in repr(failure.value.diagnostic())
    assert request.call_count <= 1 and apply.call_count <= 1
    assert transaction.backend.operations == [] and transaction.calls == []


def test_mismatched_native_binding_has_a_closed_diagnostic_before_http(transaction):
    transaction.backend.current['server_name'] = 'different.example.com'
    with mock.patch.object(CLIENT, 'request_json') as request:
        with pytest.raises(CLIENT.TrustSyncError) as failure:
            sync(transaction)
    assert failure.value.diagnostic() == {'version': 1, 'stage': 'binding', 'kind': 'value'}
    request.assert_not_called()


@pytest.mark.parametrize('value', ['private backend text', None, [], {}, True])
def test_unrecognized_failure_metadata_never_copies_arbitrary_values(value):
    failure = CLIENT.TrustSyncError(value, value)
    assert failure.diagnostic() == {'version': 1, 'stage': 'unclassified', 'kind': 'unclassified'}
    assert str(failure) == 'Relay trust synchronization failed; inspect local trust and recovery status'


@pytest.mark.parametrize('cause,kind', [
    (CLIENT.ssl.SSLCertVerificationError('private certificate'), 'protocol_tls_verify'),
    (CLIENT.ssl.SSLError('private TLS details'), 'protocol_tls'),
    (CLIENT.socket.gaierror('private hostname'), 'protocol_dns'),
    (TimeoutError('private timeout'), 'protocol_timeout'),
    (ConnectionRefusedError('private address'), 'protocol_connect'),
    (ConnectionResetError('private address'), 'protocol_connect'),
    (CLIENT.http.client.RemoteDisconnected('private response'), 'protocol_http'),
    (ValueError('private response'), 'protocol'),
])
def test_real_exception_context_is_closed_without_another_request(transaction, cause, kind):
    def request(*args, **kwargs):
        try:
            raise cause
        except Exception:
            raise ProtocolError('Console HTTPS request failed; verify connectivity and certificate trust') from None
    with mock.patch.object(CLIENT, 'request_json', side_effect=request) as network:
        with pytest.raises(CLIENT.TrustSyncError) as failure:
            sync(transaction)
    assert failure.value.diagnostic() == {'version': 1, 'stage': 'request', 'kind': kind}
    assert 'private' not in repr(failure.value.diagnostic()) and 'private' not in str(failure.value)
    network.assert_called_once()
    assert transaction.backend.operations == [] and transaction.calls == []


def test_fixed_response_refusal_is_distinct_from_unknown_protocol_text(transaction):
    for text, kind in [('Console rejected the device request; check enrollment and connectivity', 'protocol_rejected'),
                       ('private server content', 'protocol')]:
        with mock.patch.object(CLIENT, 'request_json', side_effect=ProtocolError(text)) as network:
            with pytest.raises(CLIENT.TrustSyncError) as failure:
                sync(transaction)
        assert failure.value.diagnostic() == {'version': 1, 'stage': 'request', 'kind': kind}
        network.assert_called_once()


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
