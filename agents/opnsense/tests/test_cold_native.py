"""Refuse proof changes and uncertain mutation replay without operating a guest."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest


DIRECTORY = Path(__file__).resolve().parents[1] / 'acceptance'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, DIRECTORY / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GUEST = load('cold_native_owned_guest', 'guest.py')
with patch.dict(sys.modules, {'guest': GUEST}):
    NATIVE = load('cold_native_driver_test', 'cold_native.py')
    BOOTSTRAP = load('cold_native_bootstrap_test', 'bootstrap.py')


def test_unowned_guest_is_refused_before_paths_compiler_or_commands():
    with pytest.raises(GUEST.GuestError):
        NATIVE.ColdNative(None, Path('/unrelated'), Path('/unrelated-evidence'))
    with pytest.raises(GUEST.GuestError):
        BOOTSTRAP.install_current_package(None, Path('/unrelated-source'), Path('/unrelated-sdk'), {})


def test_lost_native_enrollment_reply_is_not_replayed():
    native = object.__new__(NATIVE.ColdNative)
    native.guest = SimpleNamespace(ssh=lambda *args: None, gui_port=18443)
    with patch.object(native, 'page', side_effect=GUEST.GuestError('fixture uncertain reply')) as page:
        with pytest.raises(GUEST.GuestError):
            native.enroll('private fixture token')
        with pytest.raises(GUEST.GuestError):
            native.enroll('private fixture token')
        assert page.call_count == 1


def baseline():
    return {'enrollment_gui_key_fingerprint': 'a' * 64, 'original_cached_csr_sha256': 'b' * 64,
            'private_assignment_fingerprint': 'c' * 64, 'frpc_pid': 22, 'frpc_started': 'original start'}


@pytest.mark.parametrize('field', tuple(baseline()))
def test_changed_original_identity_never_becomes_recovery_acceptance(field):
    native = object.__new__(NATIVE.ColdNative)
    native.baseline = baseline()
    changed = {**native.baseline, field: 'changed'}
    with patch.object(native, 'probe', return_value=changed):
        with pytest.raises(GUEST.GuestError, match='changed during recovery'):
            native.wait_application('11111111-1111-4111-8111-111111111111', 'd' * 64)


def test_native_applied_flag_cannot_substitute_for_exact_issued_leaf():
    native = object.__new__(NATIVE.ColdNative)
    native.baseline, native.device = baseline(), '22222222-2222-4222-8222-222222222222'
    generation = '11111111-1111-4111-8111-111111111111'
    observed = {**native.baseline,
                'native_apply': {'phase': 'applied', 'device_id': native.device, 'generation_id': generation, 'generation': 1},
                'native_leaf_fingerprint': 'e' * 64, 'native_GUI_already_uses_enrollment_key': True,
                'native_alternate_present': True, 'native_applied_selection_and_verified_loopback_TLS_confirmed': True}
    with patch.object(native, 'probe', return_value=observed), patch.object(NATIVE.time, 'monotonic', side_effect=[0, 181]):
        with pytest.raises(GUEST.GuestError, match='not confirmed within recovery deadline'):
            native.wait_application(generation, 'd' * 64)
    assert not hasattr(native, 'applied')


def test_remove_requires_confirmed_application_before_any_page_action():
    native = object.__new__(NATIVE.ColdNative)
    with patch.object(native, 'page') as page:
        with pytest.raises(GUEST.GuestError):
            native.remove()
        page.assert_not_called()
