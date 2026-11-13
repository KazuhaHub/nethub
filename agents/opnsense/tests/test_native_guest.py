"""Keep hosted appliance preparation behind its host and signed-image boundaries."""
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/guest.py'
SPEC = importlib.util.spec_from_file_location('nethub_native_guest', SOURCE)
GUEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUEST)


def test_combined_log_capture_includes_real_stderr_decisions():
    output = GUEST.invoke([sys.executable, '-c',
        'import sys; print("startup", flush=True); '
        'print(\'{"msg":"Relay hook decision","operation":"Login","decision":"device_denied"}\', file=sys.stderr, flush=True)'],
        'private log capture', combine_output=True)
    assert output.splitlines()[0] == b'startup'
    assert json.loads(output.splitlines()[1]) == {
        'msg': 'Relay hook decision', 'operation': 'Login', 'decision': 'device_denied'}


def test_normal_command_capture_keeps_stderr_separate():
    output = GUEST.invoke([sys.executable, '-c',
        'import sys; print("public result"); print("private diagnostic", file=sys.stderr)'], 'private command')
    assert output.strip() == b'public result'


def test_failed_combined_capture_does_not_disclose_child_output():
    with pytest.raises(GUEST.GuestError, match='^private log capture failed$'):
        GUEST.invoke([sys.executable, '-c',
            'import sys; print("private value"); print("private diagnostic", file=sys.stderr); sys.exit(7)'],
            'private log capture', combine_output=True)


def test_default_guest_does_not_forward_a_console():
    assert GUEST.wan_network() == 'user,id=wan,net=10.0.2.0/24'


@pytest.mark.parametrize('port', [0, 65536, True, '443', '443;private-command'])
def test_console_forwarding_refuses_nonliteral_ports(port):
    with pytest.raises(GUEST.GuestError, match='Owned console forwarding port required'):
        GUEST.wan_network(port)


def test_console_forwarding_keeps_standard_guest_origin_and_local_targets():
    value = GUEST.wan_network(34567)
    assert value == ('user,id=wan,net=10.0.2.0/24,'
        'guestfwd=tcp:10.0.2.100:443-cmd:nc -N 127.0.0.1 34567,'
        'guestfwd=tcp:10.0.2.100:7000-cmd:nc -N 127.0.0.1 7000')


@pytest.mark.parametrize('version,accepted', [
    ('26.7', False), ('26.7.1', False), ('26.7.1_0', False), ('26.7.01_1', False),
    ('26.7.1_1', True), ('26.7.2', True), ('26.7.7_1', True), ('27.1.1', False),
])
def test_platform_minimum_requires_the_first_patch_hotfix(version, accepted):
    assert GUEST.supported_platform(version) is accepted


def test_guest_refuses_nonhosted_execution_before_creating_storage(tmp_path, monkeypatch):
    monkeypatch.setenv('GITHUB_ACTIONS', 'false')
    monkeypatch.setenv('RUNNER_ENVIRONMENT', 'github-hosted')
    target = tmp_path / 'must-not-exist'
    with pytest.raises(GUEST.GuestError, match='Fresh Linux CI with KVM is required'):
        GUEST.Guest(target)
    assert not target.exists()


def test_bad_image_bytes_never_reach_signature_command_or_vm(tmp_path, monkeypatch):
    monkeypatch.setattr(GUEST, 'download', lambda url, path, maximum: path.write_bytes(b'invalid release'))
    monkeypatch.setattr(GUEST, 'invoke', lambda *args, **kwargs: pytest.fail('untrusted image reached execution'))
    with pytest.raises(GUEST.GuestError, match='Pinned image or release key changed'):
        GUEST.verified_image(tmp_path)
    assert not (tmp_path / 'guest.qcow2').exists()


def test_serial_command_echo_cannot_hide_a_failed_exit(monkeypatch):
    nonce = 'a' * 32
    monkeypatch.setattr(GUEST.uuid, 'uuid4', lambda: SimpleNamespace(hex=nonce))

    class Connection:
        sent = b''

        def sendall(self, value):
            self.sent += value
            if value.startswith(('NH_' + nonce + '_DATA').encode()):
                reply = ('\nNH_' + nonce + ':19\r\n').encode()
            else:
                reply = b'NH_MORE> '
            self.queue = [value, reply]

        def recv(self, _maximum):
            return self.queue.pop(0)

    console = GUEST.Console.__new__(GUEST.Console)
    console.connection = Connection()
    console.log = io.BytesIO()
    console.buffer = ''
    with pytest.raises(GUEST.GuestError, match='^Owned guest bootstrap command failed$'):
        console.command('printf private-child-diagnostic\n' * 200 + 'exit 19\n')
    assert max(len(line) for line in console.connection.sent.splitlines()) <= 200


@pytest.mark.parametrize('value,category', [
    ({'success': False, 'fixture_phase': 'wan_route_missing'}, 'fixture_wan_route_missing'),
    ({'success': False, 'fixture_phase': 'wan_route_mismatch'}, 'fixture_wan_route_mismatch'),
    ({'success': False, 'fixture_phase': 'wan_route_table'}, 'fixture_wan_route_table'),
    ({'success': False, 'fixture_phase': 'wan_probe'}, 'fixture_wan_probe'),
    ({'success': False, 'fixture_phase': 'trust_store_regeneration'}, 'fixture_trust_store_regeneration'),
    ({'success': False, 'fixture_phase': 'host_effective_uid'}, 'fixture_host_effective_uid'),
    ({'success': False, 'fixture_phase': 'trust_store_regeneration',
      'fixture_context': {'kind': 'Error', 'source': 'system', 'line': 819}},
     'fixture_trust_store_regeneration_Error_system_819'),
    ({'success': False, 'fixture_phase': 'trust_store_regeneration',
      'fixture_context': {'kind': 'ErrorException', 'source': 'system', 'line': 917}},
     'fixture_trust_store_regeneration_ErrorException_system_917'),
    ({'success': False, 'fixture_phase': 'trust_store_regeneration',
      'fixture_context': {'kind': 'Error', 'source': 'private-value-must-not-escape', 'line': 1}}, 'unclassified'),
    ({'success': False, 'fixture_phase': 'trust_store_regeneration',
      'fixture_context': {'kind': [], 'source': 'system', 'line': 1}}, 'unclassified'),
    ({'success': False, 'fixture_phase': 'trust_store_regeneration',
      'fixture_context': {'kind': 'Error', 'source': 'system', 'line': True}}, 'unclassified'),
    ({'success': False, 'fixture_phase': 'trust_store_regeneration',
      'fixture_context': {'kind': 'Error', 'source': 'system', 'line': 1,
                          'message': 'private-value-must-not-escape'}}, 'unclassified'),
    ({'success': False, 'fixture_phase': {'private_value': 'private-value-must-not-escape'}}, 'unclassified'),
    ({'success': False, 'fixture_phase': 'private-value-must-not-escape'}, 'unclassified'),
    ({'success': False, 'fixture_phase': 'trust_native_save', 'private_message': 'private-value-must-not-escape'}, 'unclassified'),
    ({'success': True, 'fixture_phase': 'trust_native_save'}, 'unclassified'),
])
def test_failed_ssh_exposes_only_closed_fixture_phases(tmp_path, monkeypatch, value, category):
    guest = GUEST.Guest.__new__(GUEST.Guest)
    guest.directory, guest.ssh_port = tmp_path, 2222
    monkeypatch.setattr(GUEST.subprocess, 'run', lambda *args, **kwargs:
        SimpleNamespace(returncode=1, stdout=json.dumps(value).encode(), stderr=b''))
    with pytest.raises(GUEST.GuestError) as caught:
        guest.ssh('false\n', 'native fixture trust')
    assert str(caught.value) == 'native fixture trust failed: ' + category
    assert 'private-value' not in str(caught.value)


INSPECT = ('/usr/local/bin/php -d register_argc_argv=1 /root/nethub-ci/native-fixture.php '
           '< /root/nethub-ci/native-fixture-input.json\n')


def inspection_guest():
    guest = GUEST.Guest.__new__(GUEST.Guest)
    guest.read_only_inspection_recoveries = []
    guest.ensure_ssh = Mock(return_value=False)
    return guest


def test_healthy_read_only_inspection_never_recovers_or_replays():
    guest = inspection_guest()
    guest.ssh = Mock(return_value=b'original result')
    assert guest.ssh_read_only_inspection(INSPECT) == b'original result'
    guest.ssh.assert_called_once_with(INSPECT, 'native fixture inspect')
    guest.ensure_ssh.assert_not_called()
    assert guest.read_only_inspection_recoveries == []


@pytest.mark.parametrize('category', ['guest_ssh_connection_refused', 'guest_ssh_connect_timeout', 'guest_ssh_connection_reset'])
@pytest.mark.parametrize('listener_started', [False, True])
def test_transport_failure_recovers_only_one_identical_read(category, listener_started):
    guest = inspection_guest()
    guest.ssh = Mock(side_effect=[GUEST.GuestError('native fixture inspect failed: ' + category), b'verified read'])
    guest.ensure_ssh.return_value = listener_started
    assert guest.ssh_read_only_inspection(INSPECT) == b'verified read'
    assert guest.ssh.call_count == 2 and all(call.args == (INSPECT, 'native fixture inspect') for call in guest.ssh.call_args_list)
    guest.ensure_ssh.assert_called_once_with()
    result = guest.read_only_inspection_recoveries
    GUEST.validate_read_only_inspection_recoveries(result, require_completed=True)
    assert result[0]['first_transport_failure'] == category
    assert result[0]['listener_recovery'] == ('started_and_verified' if listener_started else 'probe_only')


@pytest.mark.parametrize('failure', ['guest_ssh_authentication', 'guest_ssh_host_key', 'fixture_native_gui_identity', 'unclassified'])
def test_identity_or_command_failures_are_not_repaired(failure):
    guest = inspection_guest()
    guest.ssh = Mock(side_effect=GUEST.GuestError('native fixture inspect failed: ' + failure))
    with pytest.raises(GUEST.GuestError):
        guest.ssh_read_only_inspection(INSPECT)
    assert guest.ssh.call_count == 1 and guest.read_only_inspection_recoveries == []
    guest.ensure_ssh.assert_not_called()


def test_mutation_cannot_use_the_read_only_recovery_entry_point():
    guest = inspection_guest()
    guest.ssh = Mock()
    with pytest.raises(GUEST.GuestError, match='Only the fixed read-only'):
        guest.ssh_read_only_inspection('/usr/local/sbin/configctl nethub-agent rotate\n')
    guest.ssh.assert_not_called()
    guest.ensure_ssh.assert_not_called()


@pytest.mark.parametrize('fail_listener', [False, True])
def test_failed_recovery_remains_failed_and_does_not_loop(fail_listener):
    guest = inspection_guest()
    initial = GUEST.GuestError('native fixture inspect failed: guest_ssh_connect_timeout')
    final = GUEST.GuestError('read boundary unavailable')
    guest.ssh = Mock(side_effect=[initial, final])
    if fail_listener:
        guest.ensure_ssh.side_effect = final
    with pytest.raises(GUEST.GuestError, match='read boundary unavailable'):
        guest.ssh_read_only_inspection(INSPECT)
    guest.ensure_ssh.assert_called_once_with()
    assert guest.ssh.call_count == (1 if fail_listener else 2)
    result = guest.read_only_inspection_recoveries
    GUEST.validate_read_only_inspection_recoveries(result)
    assert result[0]['phase'] == 'failed' and not result[0]['read_completed']
    with pytest.raises(ValueError):
        GUEST.validate_read_only_inspection_recoveries(result, require_completed=True)


def test_read_only_recovery_budget_is_not_reset_after_success():
    guest = inspection_guest()
    item = {'first_transport_failure': 'guest_ssh_connect_timeout', 'phase': 'completed',
            'listener_recovery': 'probe_only', 'read_completed': True, 'elapsed_ms': 1}
    guest.read_only_inspection_recoveries = [dict(item) for _ in range(4)]
    guest.ssh = Mock(side_effect=GUEST.GuestError('native fixture inspect failed: guest_ssh_connect_timeout'))
    with pytest.raises(GUEST.GuestError):
        guest.ssh_read_only_inspection(INSPECT)
    assert guest.ssh.call_count == 1 and len(guest.read_only_inspection_recoveries) == 4
    guest.ensure_ssh.assert_not_called()


@pytest.mark.parametrize('category', ['guest_ssh_authentication', 'guest_ssh_host_key', 'unclassified'])
def test_listener_recovery_never_bypasses_credential_or_host_key_refusal(category):
    guest = GUEST.Guest.__new__(GUEST.Guest)
    guest.ssh = Mock(side_effect=GUEST.GuestError('existing owned SSH probe failed: ' + category))
    guest.console = Mock()
    with pytest.raises(GUEST.GuestError):
        guest.ensure_ssh()
    guest.console.command.assert_not_called()


def test_listener_recovery_uses_only_the_original_private_configuration():
    guest = GUEST.Guest.__new__(GUEST.Guest)
    guest.process = SimpleNamespace(poll=lambda: None)
    guest.console = Mock()
    guest.ssh = Mock(side_effect=[GUEST.GuestError('existing owned SSH probe failed: guest_ssh_connect_timeout'), b''])
    assert guest.ensure_ssh() is True
    guest.console.command.assert_called_once()
    command = guest.console.command.call_args.args[0]
    assert '-f /root/nethub-ci/sshd.conf' in command
    assert all(token not in command for token in ('configctl', 'agentctl', 'frpc', 'sshd_config'))


def test_read_only_recovery_projection_rejects_private_or_inconsistent_fields():
    item = {'first_transport_failure': 'guest_ssh_connect_timeout', 'phase': 'completed',
            'listener_recovery': 'probe_only', 'read_completed': True, 'elapsed_ms': 1}
    for change in ({'private_message': 'private-peer'}, {'elapsed_ms': True}, {'elapsed_ms': -1},
                   {'first_transport_failure': 'private-peer'}, {'listener_recovery': 'unconfirmed'},
                   {'read_completed': False}):
        with pytest.raises(ValueError):
            GUEST.validate_read_only_inspection_recoveries([dict(item, **change)])
