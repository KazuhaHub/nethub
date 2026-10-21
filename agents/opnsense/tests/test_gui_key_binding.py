"""Check the optional key contract and acknowledgement before native key wiring."""
import base64
import copy
import json
from unittest import mock

import pytest
import test_protocol as wire
import test_enrollment as enrollment

BOUND = json.loads((wire.PROTO / 'examples/valid/enroll-bound-request.json').read_text())
RESPONSE = json.loads((wire.PROTO / 'examples/valid/enroll-bound-response.json').read_text())


def test_bound_request_and_fingerprint_match_shared_examples():
    actual = wire.AGENT.build_enroll_request(BOUND['enroll_token'], BOUND['platform_version'],
                                            BOUND['agent_version'], BOUND['hostname'],
                                            gui_public_key=BOUND['gui_public_key'])
    assert actual == dict(BOUND, agent_protocol_version=wire.AGENT.VERSION)
    assert wire.AGENT.gui_key_fingerprint(BOUND['gui_public_key']) == RESPONSE['gui_key_fingerprint']
    wire.validator('enroll-request.schema.json').validate(actual)


@pytest.mark.parametrize('value', [None, '', True, 'A'*122, BOUND['gui_public_key']+'=',
                                  BOUND['gui_public_key'][:121]+'B'])
def test_invalid_public_keys_have_fixed_errors(value):
    with pytest.raises(wire.AGENT.ProtocolError, match='^Invalid certificate public key$'):
        wire.AGENT.gui_key_fingerprint(value)


def test_noncanonical_or_off_curve_points_are_rejected():
    raw = base64.urlsafe_b64decode(BOUND['gui_public_key']+'==')
    for value in [raw[:27]+bytes(64), raw[:27]+b'\xff'*64, raw[:10]+b'\x00'+raw[11:]]:
        with pytest.raises(wire.AGENT.ProtocolError):
            wire.AGENT.gui_key_fingerprint(base64.urlsafe_b64encode(value).decode().rstrip('='))


def test_network_helper_requires_exact_binding_acknowledgement():
    for fingerprint in [RESPONSE['gui_key_fingerprint'], None, '0'*64]:
        response = copy.deepcopy(RESPONSE)
        if fingerprint is None:
            del response['gui_key_fingerprint']
        else:
            response['gui_key_fingerprint'] = fingerprint
        with mock.patch.object(enrollment.ENROLL, 'request_json', return_value=response) as network:
            call = lambda: enrollment.ENROLL.request_enrollment(
                'https://console.example.test', BOUND['enroll_token'], BOUND['platform_version'],
                BOUND['agent_version'], BOUND['hostname'], gui_public_key=BOUND['gui_public_key'])
            if fingerprint == RESPONSE['gui_key_fingerprint']:
                assert call()['gui_key_fingerprint'] == fingerprint
            else:
                with pytest.raises(enrollment.ENROLL.ProtocolError, match='Server did not confirm'):
                    call()
            assert network.call_args.args[2]['gui_public_key'] == BOUND['gui_public_key']


@pytest.mark.parametrize('value', [None, '', True, 'A'*64, 'a'*63, 'a'*65])
def test_malformed_optional_fingerprint_is_not_ignored(value):
    with pytest.raises(enrollment.ENROLL.ProtocolError, match='^Invalid enrollment response$'):
        enrollment.ENROLL.validate_response(dict(RESPONSE, gui_key_fingerprint=value))


def test_legacy_unbound_response_remains_valid():
    response = dict(enrollment.SAMPLE, agent_protocol_version='1.0.0')
    assert 'gui_key_fingerprint' not in enrollment.ENROLL.validate_response(response)
