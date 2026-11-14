"""Refuse unconfirmed native DNS provisioning without replaying fixture actions."""
import importlib.util
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/console_dns.py'
sys.path.insert(0, str(SOURCE.parent))
try:
    SPEC = importlib.util.spec_from_file_location('native_console_dns', SOURCE)
    SUITE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(SUITE)
finally:
    sys.path.pop(0)


@pytest.mark.parametrize('receipt', [None, True, [], {}, {'configured': False},
    {'configured': 1}, {'configured': 'true'}, {'configured': True, 'extra': 'private'}])
def test_unconfirmed_native_dns_cannot_activate(receipt):
    guest, fixture = Mock(), Mock(return_value=receipt)
    with pytest.raises(SUITE.GuestError, match='Native console DNS fixture unavailable'):
        SUITE.provision(guest, fixture)
    fixture.assert_called_once_with('console-dns')
    guest.ssh.assert_not_called()


def test_failed_native_activation_is_not_replayed():
    guest, fixture = Mock(), Mock(return_value={'configured': True})
    guest.ssh.side_effect = SUITE.GuestError('activation failed')
    with pytest.raises(SUITE.GuestError, match='activation failed'):
        SUITE.provision(guest, fixture)
    fixture.assert_called_once_with('console-dns')
    assert guest.ssh.call_count == 1


def test_failed_module_staging_cannot_create_or_activate_override():
    guest, fixture = Mock(), Mock()
    guest.put.side_effect = SUITE.GuestError('staging failed')
    with pytest.raises(SUITE.GuestError, match='staging failed'):
        SUITE.provision(guest, fixture)
    fixture.assert_not_called()
    guest.ssh.assert_not_called()
