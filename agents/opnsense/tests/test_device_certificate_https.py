"""Use real verified HTTPS through the shared transport, without patched helpers."""
import json
from pathlib import Path

import pytest

from test_enrollment import https_console
import enrollment
import certificate_protocol
import relay_trust_protocol
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'agents/opnsense/plugin/tests'))
from test_relay_trust_transaction import transaction
from relay_trust_sync import TrustSynchronizer


def example(name):
    return json.loads((ROOT/'proto/examples/valid'/(name+'.json')).read_text())


@pytest.mark.parametrize('suffix', ['gui-certificate/settings', 'gui-certificate/request', 'gui-certificate/issued',
    'gui-certificate/applied', 'relay-trust/settings', 'relay-trust/applied'])
def test_each_exact_certificate_endpoint_reaches_real_tls(suffix, https_console, monkeypatch):
    port, context, calls, state = https_console
    state.update(status=200, body=b'{"fixture":true}')
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
    path = '/api/v1/devices/'+suffix
    body = relay_trust_protocol.settings_request(example('relay-trust-settings-request')['device_id'])
    assert enrollment.request_json(f'https://localhost:{port}', path, body, secret='A'*43, context=context) == {'fixture': True}
    assert calls == [(path, body)] and state['authorizations'] == [['Bearer '+'A'*43]]
    with pytest.raises(enrollment.ProtocolError):
        enrollment.request_json(f'https://localhost:{port}', path, body, secret='A'*43)
    assert len(calls) == 1


def test_actual_gui_certificate_settings_helper_uses_verified_shared_transport(https_console):
    port, context, calls, state = https_console
    value = example('certificate-settings-response'); state.update(status=200, body=json.dumps(value).encode())
    actual = certificate_protocol.request_settings(f'https://localhost:{port}', 'A'*43, value['device_id'],
        value['assigned_host'].split('.')[0], value['gui_key_fingerprint'], context=context)
    assert actual == value and calls[0][0] == '/api/v1/devices/gui-certificate/settings'


@pytest.mark.parametrize('suffix', ['relay-trust/other', 'relay-trust/applied?other=1', 'gui-certificate/settings/'])
def test_unlisted_certificate_endpoint_never_connects(https_console, suffix):
    port, context, calls, state = https_console
    with pytest.raises(enrollment.ProtocolError, match='Invalid device endpoint'):
        enrollment.request_json(f'https://localhost:{port}', '/api/v1/devices/'+suffix, {}, context=context)
    assert calls == []


def test_real_https_trust_application_and_receipt_retry_are_separate(https_console, transaction):
    port, context, calls, state = https_console
    value = example('relay-trust-settings-response')
    settings = '/api/v1/devices/relay-trust/settings'
    applied = '/api/v1/devices/relay-trust/applied'
    state['responses'] = {settings: {'status': 200, 'body': json.dumps(value).encode()},
                          applied: {'status': 409, 'body': b'{"code":"relay_trust_changed"}'}}
    worker = TrustSynchronizer(transaction)
    args = (f'https://localhost:{port}', 'A'*43, value['device_id'], value['desired']['server_name'])
    assert worker.sync(*args, context=context)['phase'] == 'applied_unconfirmed'
    assert transaction.read()['phase'] == 'applied' and transaction.read()['receipt'] is None
    reply = example('relay-trust-applied-response')
    state['responses'][applied] = {'status': 200, 'body': json.dumps(reply).encode()}
    assert worker.sync(*args, context=context)['confirmed'] is True
    assert [call[0] for call in calls] == [settings, applied, settings, applied]
    assert state['authorizations'] == [['Bearer '+'A'*43]]*4
    assert transaction.backend.operations == ['install'] and transaction.calls == ['reload']
