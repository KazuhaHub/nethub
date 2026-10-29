"""Refuse incomplete native shared-token recovery evidence."""
import importlib.util
from pathlib import Path
import sys

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/shared_token.py'
sys.path.insert(0, str(SOURCE.parent))
try:
    SPEC = importlib.util.spec_from_file_location('native_shared_token_test', SOURCE)
    SUITE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(SUITE)
finally:
    sys.path.pop(0)


def original():
    return {'frp_token': 'old-token', 'device_secret': 'old-bearer', 'domain_claim': 'old-claim',
            'device_id': 'stable-id', 'enabled': '1', 'console_url': 'https://console.example.com',
            'relay_ca': 'retained-trust', 'server_name': 'console.example.com', 'circuit_breaker': '0'}


def replacement():
    return dict(original(), frp_token='new-token', device_secret='new-bearer', domain_claim='new-claim')


def test_complete_replacement_retains_native_identity_and_policy():
    SUITE.validate_native_replacement(original(), replacement())


@pytest.mark.parametrize('field', tuple(original()))
def test_partial_credentials_or_changed_native_policy_are_not_recovery(field):
    before, after = original(), replacement()
    after[field] = before[field] if field in ('frp_token', 'device_secret', 'domain_claim') else 'changed'
    with pytest.raises(SUITE.GuestError, match='changed policy or retained old credentials'):
        SUITE.validate_native_replacement(before, after)


@pytest.mark.parametrize('change', ['missing', 'extra', 'empty', 'wrong_type'])
def test_ambiguous_native_projection_cannot_supply_a_recovery_receipt(change):
    before, after = original(), replacement()
    if change == 'missing':
        del before['frp_token']
        del after['frp_token']
    elif change == 'extra':
        after['unknown'] = 'private'
    else:
        after['frp_token'] = '' if change == 'empty' else True
    with pytest.raises(SUITE.GuestError):
        SUITE.validate_native_replacement(before, after)
