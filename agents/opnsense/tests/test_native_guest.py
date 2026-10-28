"""Keep hosted appliance preparation behind its host and signed-image boundaries."""
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/guest.py'
SPEC = importlib.util.spec_from_file_location('nethub_native_guest', SOURCE)
GUEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUEST)


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
