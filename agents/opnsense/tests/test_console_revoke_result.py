"""Refuse false timing, leaked fields and broadened console-Revoke claims."""
import copy
import importlib.util
from pathlib import Path

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/console_revoke_result.py'
SPEC = importlib.util.spec_from_file_location('console_revoke_result', SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def receipt():
    return {'version': 1, 'passed': True, 'phase': 'completed', 'deadline_ms': 5000,
        'clock_start': 'before normal console confirmation click',
        'isolated_console_CA_exception': True, 'public_network_acceptance': False,
        'full_W5_acceptance': False, 'confirmation_dispatch_utc': '2026-11-12T01:00:00.000Z',
        'server_revoked_at_utc': '2026-11-12T01:00:00.100Z', 'console_response_ms': 101,
        'native_proxy_offline_ms': 1200, 'normal_browser_CSRF_protected_revoke': True,
        'no_reconnect_observation_ms': 30000, 'csp_violations': 0, 'browser_errors': 0,
        'external_requests': 0,
        'samples': [{'elapsed_ms': 1, 'proxy_online': True}, {'elapsed_ms': 1200, 'proxy_online': False}]}


def test_exact_browser_and_native_scopes_are_separate():
    value = receipt()
    assert MODULE.validate(value) == value
    with pytest.raises(ValueError):
        MODULE.validate(value, native=True)
    value.update({key: True for key in MODULE.NATIVE_FIELDS})
    assert MODULE.validate(value, native=True) == value
    with pytest.raises(ValueError):
        MODULE.validate(value)


@pytest.mark.parametrize('key,bad', [('passed', False), ('phase', 'pending'),
    ('deadline_ms', 5001), ('native_proxy_offline_ms', -1), ('native_proxy_offline_ms', 5001),
    ('native_proxy_offline_ms', True), ('clock_start', 'after database commit'),
    ('no_reconnect_observation_ms', 29999), ('console_response_ms', 0),
    ('public_network_acceptance', True), ('full_W5_acceptance', True),
    ('normal_browser_CSRF_protected_revoke', False), ('csp_violations', 1),
    ('browser_errors', 1), ('external_requests', 1), ('server_revoked_at_utc', 'private fixture text'),
    ('confirmation_dispatch_utc', '2026-11-12T01:00:00')])
def test_malformed_or_overstated_receipts_are_refused(key, bad):
    value = receipt()
    value[key] = bad
    with pytest.raises(ValueError):
        MODULE.validate(value)


@pytest.mark.parametrize('mutation', ['secret', 'sample_secret', 'missing_live', 'missing_offline',
    'backwards', 'late', 'mismatched_cutoff', 'extra_offline', 'boolean_time'])
def test_raw_fields_and_false_sample_sequences_are_refused(mutation):
    value = copy.deepcopy(receipt())
    if mutation == 'secret':
        value['password'] = 'private-fixture-sentinel'
    elif mutation == 'sample_secret':
        value['samples'][0]['address'] = 'private-fixture-sentinel'
    elif mutation == 'missing_live':
        value['samples'] = value['samples'][1:]
    elif mutation == 'missing_offline':
        value['samples'] = value['samples'][:1]
    elif mutation == 'backwards':
        value['samples'][0]['elapsed_ms'] = 1201
    elif mutation == 'late':
        value['samples'][-1]['elapsed_ms'] = 5001
    elif mutation == 'mismatched_cutoff':
        value['samples'][-1]['elapsed_ms'] = 1199
    elif mutation == 'extra_offline':
        value['samples'].append({'elapsed_ms': 1300, 'proxy_online': False})
    else:
        value['samples'][0]['elapsed_ms'] = True
    with pytest.raises(ValueError):
        MODULE.validate(value)
