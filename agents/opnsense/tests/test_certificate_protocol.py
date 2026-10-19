"""Exercise actual agent public request/response helpers against shared contracts."""
import copy
import json
from pathlib import Path
import sys
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'agents/opnsense/plugin/src/usr/local/opnsense/scripts/nethub-agent'))
import certificate_protocol as CLIENT
from protocol import ProtocolError


def example(name):
    return json.loads((ROOT / 'proto/examples/valid' / (name + '.json')).read_text())


def parse(value):
    expected = example('certificate-submit-response')
    return CLIENT.settings(value, expected['device_id'], expected['assigned_host'].split('.')[0], expected['gui_key_fingerprint'])


def test_actual_agent_builder_and_parser_match_shared_examples():
    request = example('certificate-submit-request')
    assert CLIENT.build_request(request['device_id'], request['csr_der']) == request
    for name in ['certificate-settings-response', 'certificate-submit-response']:
        value = example(name)
        assert parse(value) == value
        extended = copy.deepcopy(value)
        extended['future_extension'] = True
        if extended['request'] is not None:
            extended['request']['future_extension'] = True
        assert parse(extended) == value


@pytest.mark.parametrize('changes', [
    {'agent_protocol_version': '1.1.0'}, {'agent_protocol_version': '2.0.0'},
    {'agent_protocol_version': '1.02.0'}, {'device_id': '00000000-0000-0000-0000-000000000000'},
    {'assigned_host': 'abcd1234.other.example.com\n'}, {'assigned_host': 'other123.devices.example.com'},
    {'gui_key_fingerprint': '0' * 64}, {'request': False},
])
def test_wrong_assignment_or_version_fails_without_echoing(changes):
    value = example('certificate-submit-response')
    value.update(changes)
    with pytest.raises(ProtocolError, match='^Invalid certificate acknowledgement$'):
        parse(value)


@pytest.mark.parametrize('changes', [
    {'request_id': None}, {'csr_der': 'AA=='}, {'csr_der': '\nAA=='},
    {'csr_der': '_' * 100}, {'csr_der': 'A' * 5468}, {'csr_fingerprint': '0' * 64},
    {'created_at': '2026-02-30T00:00:00.000000Z'}, {'created_at': '2026-10-19T00:00:00Z'},
])
def test_malformed_record_is_not_accepted_as_cache_recovery(changes):
    value = example('certificate-submit-response')
    value['request'].update(changes)
    with pytest.raises(ProtocolError, match='^Invalid certificate acknowledgement$'):
        parse(value)


def test_submit_checks_exact_readback_and_uses_existing_authenticated_transport():
    response = example('certificate-submit-response')
    args = ('https://console.example.com', 'public-test-placeholder', response['device_id'],
            'abcd1234', response['gui_key_fingerprint'], response['request']['csr_der'])
    with mock.patch.object(CLIENT, 'request_json', return_value=response) as request:
        assert CLIENT.submit_request(*args) == response
        assert request.call_args.args[1] == '/api/v1/devices/gui-certificate/request'
        assert request.call_args.kwargs['secret'] == args[1]
    with mock.patch.object(CLIENT, 'request_json', return_value=example('certificate-settings-response')):
        with pytest.raises(ProtocolError):
            CLIENT.submit_request(*args)
