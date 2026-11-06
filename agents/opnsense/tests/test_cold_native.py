"""Refuse proof changes and uncertain mutation replay without operating a guest."""
import importlib.util
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

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


def test_initial_submission_retries_only_an_explicit_busy_result_before_baseline():
    native = object.__new__(NATIVE.ColdNative)
    native.guest = SimpleNamespace(ssh=Mock(side_effect=[
        '{"success":false,"action":"busy"}',
        '{"success":true,"action":"certificate","phase":"pending"}',
    ]))
    original = {'original_cached_csr_sha256': 'a' * 64}
    with patch.object(native, 'probe', return_value=original), patch.object(NATIVE.time, 'sleep'):
        assert native.initial_request() == original
    assert native.guest.ssh.call_count == 2 and native.original_request == original


def initial_submission_script():
    native = object.__new__(NATIVE.ColdNative)
    native.guest = SimpleNamespace(ssh=Mock(return_value='{"success":true,"phase":"pending"}'))
    with patch.object(native, 'probe', return_value={'original_cached_csr_sha256': 'a' * 64}):
        native.initial_request()
    return native.guest.ssh.call_args.args[0]


def test_initial_submission_uses_the_shipped_bounded_cli_with_its_internal_lock():
    cron = (DIRECTORY.parent / 'plugin/src/usr/local/etc/cron.d/nethub-agent').read_text()
    line = next(line for line in cron.splitlines() if 'agentctl.py --locked certificate ' in line)
    tokens = shlex.split(line.split('&& ', 1)[1].split(' >>', 1)[0])
    assert tokens[3:8] == ['/usr/bin/lockf', '-sk', '-t', '0', '/var/db/nethub-agent/reconcile.lock']
    assert tokens[-2:] == ['--locked', 'certificate']
    # Outside cron's external lock, use the CLI's own normal lock acquisition.
    expected = tokens[:3] + tokens[8:-2] + ['certificate']
    script = initial_submission_script()
    assert shlex.split(script.removeprefix('if ').split('; then', 1)[0]) == expected


@pytest.mark.parametrize('status,accepted', [(0, True), (1, True), (125, False)])
def test_initial_cli_exit_adapter_retains_json_but_refuses_transport_failure(status, accepted):
    shell = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('sh')
    assert shell and Path(shell).is_file()
    script = initial_submission_script()
    command = script.removeprefix('if ').split('; then', 1)[0]
    controlled = script.replace(command, "printf '%s\\n' '{\"success\":false,\"action\":\"busy\"}'; (exit " + str(status) + ')', 1)
    result = subprocess.run([shell, '-s'], input=controlled, text=True, capture_output=True, timeout=10)
    assert (result.returncode == 0) is accepted
    assert result.stdout == '{"success":false,"action":"busy"}\n'


def test_initial_submission_failure_is_not_replayed_or_exported():
    native = object.__new__(NATIVE.ColdNative)
    native.guest = SimpleNamespace(ssh=Mock(return_value=
        '{"success":false,"phase":"error","message":"private token and URL"}'))
    with patch.object(native, 'probe') as probe:
        with pytest.raises(GUEST.GuestError, match='submission failed') as caught:
            native.initial_request()
    native.guest.ssh.assert_called_once()
    probe.assert_not_called()
    assert 'private' not in str(caught.value) and not hasattr(native, 'original_request')


def test_initial_submission_busy_deadline_cannot_become_acceptance():
    native = object.__new__(NATIVE.ColdNative)
    native.guest = SimpleNamespace(ssh=Mock(return_value='{"success":false,"action":"busy"}'))
    with patch.object(NATIVE.time, 'monotonic', side_effect=[0, 16]), patch.object(native, 'probe') as probe:
        with pytest.raises(GUEST.GuestError, match='lock remained busy'):
            native.initial_request()
    probe.assert_not_called()
    assert not hasattr(native, 'original_request')


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
