"""Shared trust wire builders do not install files or imply verified application."""
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'agents/opnsense/plugin/src/usr/local/opnsense/scripts/nethub-agent'))
from protocol import ProtocolError, VERSION
import relay_trust_protocol as CLIENT


def example(name):
    return json.loads((ROOT/'proto/examples/valid'/(name+'.json')).read_text())


def test_request_builders_match_shared_examples():
    expected = example('relay-trust-settings-request')
    expected['agent_protocol_version'] = VERSION
    actual = CLIENT.settings_request(expected['device_id'])
    assert actual == expected
    expected = example('relay-trust-applied-request')
    expected['agent_protocol_version'] = VERSION
    actual = CLIENT.applied_request(expected['device_id'], expected['generation_id'], expected['generation'], expected['bundle_fingerprint'])
    assert actual == expected


def test_actual_wire_builders_validate_against_shared_schemas():
    pytest.importorskip('jsonschema')
    from test_protocol import validator
    expected = example('relay-trust-applied-request')
    validator('relay-trust-settings-request.schema.json').validate(CLIENT.settings_request(expected['device_id']))
    validator('relay-trust-applied-request.schema.json').validate(CLIENT.applied_request(
        expected['device_id'], expected['generation_id'], expected['generation'], expected['bundle_fingerprint']))


@pytest.mark.parametrize('field,value', [('generation', True), ('generation', 0), ('generation', 1.5),
    ('generation', 2147483648), ('generation_id', 'invalid'),
    ('generation_id', '00000000-0000-0000-0000-000000000000'),
    ('bundle_fingerprint', 'A'*64), ('bundle_fingerprint', None)])
def test_invalid_identity_cannot_be_reported(field, value):
    expected = example('relay-trust-applied-request')
    expected[field] = value
    with pytest.raises(ProtocolError):
        CLIENT.applied_request(expected['device_id'], expected['generation_id'], expected['generation'], expected['bundle_fingerprint'])
