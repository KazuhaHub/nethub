"""Check bound delivery wire parsing; independent native trust is a later step."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'agents/opnsense/plugin/src/usr/local/opnsense/scripts/nethub-agent'))
import certificate_protocol as CLIENT
from protocol import ProtocolError, VERSION


def example(name):
    return json.loads((ROOT / 'proto/examples/valid' / (name + '.json')).read_text())


def parse(value):
    original = example('certificate-issued-response')
    return CLIENT.delivery(value, original['device_id'], original['assigned_host'].split('.')[0],
                           original['gui_key_fingerprint'], original['request'],
                           now=datetime(2026, 10, 19, 12, tzinfo=timezone.utc))


def test_delivery_public_material_and_pending_keep_original_request():
    for name in ['certificate-issued-response', 'certificate-issued-pending-response']:
        value = example(name)
        assert parse(value) == value
    value = example('certificate-issued-response')
    for i in range(16):
        value['future' + str(i)] = True
        value['issued']['future' + str(i)] = True
    result = parse(value)
    assert len(result) == 6 and len(result['issued']) == 8
    value['one_too_many'] = True
    with pytest.raises(ProtocolError):
        parse(value)


@pytest.mark.parametrize('mutate', [
    lambda v: v.update(agent_protocol_version='1.2.0'),
    lambda v: v.update(agent_protocol_version='2.0.0'),
    lambda v: v.update(request=None),
    lambda v: v.update(assigned_host='different.devices.example.com'),
    lambda v: v.update(gui_key_fingerprint='a' * 64),
    lambda v: v['request'].update(request_id='00000000-0000-0000-0000-000000000000'),
    lambda v: v['request'].update(created_at='2026-10-18T00:00:00.000000Z'),
    lambda v: v['issued'].update(generation=True),
    lambda v: v['issued'].update(generation=0),
    lambda v: v['issued'].update(generation=2147483648),
    lambda v: v['issued'].update(generation_id='not-a-generation'),
    lambda v: v['issued'].update(leaf_fingerprint='0' * 64),
    lambda v: v['issued'].update(chain_pem=v['issued']['chain_pem'] + 'trailing'),
    lambda v: v['issued'].update(chain_pem=v['issued']['chain_pem'].replace('\n', '\r\n')),
    lambda v: v['issued'].update(chain_pem='x' * 32769),
    lambda v: v['issued'].update(chain_pem=v['issued']['chain_pem'] * 2),
    lambda v: v['issued'].update(not_before='2026-01-01T00:00:00Z'),
    lambda v: v['issued'].update(not_before='2030-01-01T00:00:00.000000Z'),
    lambda v: v['issued'].update(valid_until='2026-10-18T00:00:00.000000Z'),
    lambda v: v['issued'].update(valid_until='2040-01-01T00:00:00.000000Z'),
    lambda v: v['issued'].update(renew_after=v['issued']['valid_until']),
])
def test_delivery_rejects_unbound_corrupt_or_expired_wire_material(mutate):
    value = copy.deepcopy(example('certificate-issued-response'))
    mutate(value)
    with pytest.raises(ProtocolError):
        parse(value)


def test_issued_request_sends_only_identity_and_original_public_pins():
    value = example('certificate-issued-response')
    with mock.patch.object(CLIENT, 'request_json', return_value=value) as request:
        result = CLIENT.request_issued('https://console.example.test', 'opaque-device-secret',
                                      value['device_id'], value['assigned_host'].split('.')[0],
                                      value['gui_key_fingerprint'], value['request'])
    assert result == value
    args, kwargs = request.call_args
    assert args[:2] == ('https://console.example.test', '/api/v1/devices/gui-certificate/issued')
    assert args[2] == dict(agent_protocol_version=VERSION, device_id=value['device_id'],
                          request_id=value['request']['request_id'], csr_fingerprint=value['request']['csr_fingerprint'])
    assert kwargs['secret'] == 'opaque-device-secret'
    wrong = dict(value['request'], csr_fingerprint='0' * 64)
    with mock.patch.object(CLIENT, 'request_json') as request:
        with pytest.raises(ProtocolError):
            CLIENT.request_issued('https://console.example.test', 'opaque-device-secret',
                                  value['device_id'], value['assigned_host'].split('.')[0],
                                  value['gui_key_fingerprint'], wrong)
        request.assert_not_called()
