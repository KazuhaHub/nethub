"""Refuse substituted replay material; these controls do not prove native recovery."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'agents/opnsense/acceptance/committed_trust_replay.py'
sys.path.insert(0, str(SOURCE.parent))
try:
    SPEC = importlib.util.spec_from_file_location('committed_trust_replay_controls', SOURCE)
    SUITE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(SUITE)
finally:
    sys.path.pop(0)


@pytest.fixture
def retained():
    wire = json.loads((ROOT / 'proto/examples/valid/rotate-response.json').read_text(encoding='utf-8'))
    before = {key: wire[key] for key in
              ('device_id', 'frp_token', 'server_addr', 'server_name', 'subdomain')}
    before.update(server_port=str(wire['server_port']), domain_claim='previous signed claim',
                  relay_ca=base64.b64encode(wire['relay_ca_pem'].encode('ascii')).decode('ascii'))
    return wire, before, {'operation_id': wire['operation_id'], 'candidate': wire['device_secret']}


def test_exact_committed_assignment_is_correlated_with_original_bundle(retained):
    wire, before, pending = retained
    SUITE.validate_response(wire, before, pending)


@pytest.mark.parametrize('field', ['operation_id', 'device_secret', 'relay_ca_pem',
                                   'server_addr', 'server_name', 'server_port', 'domain_claim'])
def test_replay_cannot_substitute_an_operation_candidate_route_or_current_bundle(retained, field):
    wire, before, pending = retained
    changed = copy.deepcopy(wire)
    changed[field] = before['domain_claim'] if field == 'domain_claim' else 'different public fixture'
    with pytest.raises(SUITE.GuestError, match='retain its original assignment and trust'):
        SUITE.validate_response(changed, before, pending)


def trust_pair(retained):
    public = retained[0]['relay_ca_pem']
    desired = {'generation_id': '11111111-1111-4111-8111-111111111111', 'generation': 3,
               'ca_pem': public,
               'bundle_fingerprint': hashlib.sha256(b'nethub-relay-trust-v1:' + public.encode('ascii')).hexdigest()}
    metadata = {key: desired[key] for key in ('generation_id', 'generation', 'bundle_fingerprint')}
    model = {'relay_ca': base64.b64encode(public.encode('ascii')).decode('ascii'),
             'relay_trust_state': base64.b64encode(json.dumps(metadata).encode('ascii')).decode('ascii')}
    return model, desired


def test_scheduled_completion_must_match_the_authenticated_generation_and_bytes(retained):
    model, desired = trust_pair(retained)
    SUITE.validate_current_trust(model, desired)


@pytest.mark.parametrize('part', ['bytes', 'generation', 'fingerprint', 'encoding'])
def test_scheduled_completion_cannot_hide_a_different_or_malformed_trust(retained, part):
    model, desired = trust_pair(retained)
    if part == 'bytes':
        model['relay_ca'] = base64.b64encode(b'other public certificate material').decode('ascii')
    elif part == 'encoding':
        model['relay_trust_state'] = 'invalid base64'
    else:
        metadata = json.loads(base64.b64decode(model['relay_trust_state']))
        metadata['generation' if part == 'generation' else 'bundle_fingerprint'] = 4 if part == 'generation' else '0' * 64
        model['relay_trust_state'] = base64.b64encode(json.dumps(metadata).encode('ascii')).decode('ascii')
    with pytest.raises(SUITE.GuestError, match='differs from the authenticated head'):
        SUITE.validate_current_trust(model, desired)
