"""Check closed native replies, restart boundaries and genuine loopback TLS."""
import contextlib
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
from unittest import mock

import pytest

from test_certificate_chain import chain, HOST
from certificate_backend import NativeGuiBackend, NativeGuiError
from certificate_transaction import CertificatePreparationRequired


IDENTITY = {'nonce': 'a' * 32, 'snapshot_sha256': 'b' * 64, 'candidate_sha256': 'c' * 64}


def child(result, code=0):
    return subprocess.CompletedProcess([], code, json.dumps(result).encode(), b'private child diagnostic')


def test_boot_rollback_never_restarts_or_installs_a_gui():
    run = mock.Mock(return_value=child({'success': True, 'result': {'restored': True, 'changed': True}}))
    backend = NativeGuiBackend(None, boot=True, run=run)
    with mock.patch('certificate_backend.os.geteuid', return_value=0, create=True):
        assert backend.rollback(IDENTITY) is True
        with pytest.raises(NativeGuiError):
            backend.install(IDENTITY)
    assert run.call_count == 1
    assert run.call_args.args[0][0] == '/usr/local/bin/php'
    assert run.call_args.kwargs['timeout'] == 5 and backend.probe(IDENTITY) is False


@pytest.mark.parametrize('changed', [True, False])
def test_native_install_restarts_only_the_gui_when_configuration_changed(changed):
    responses = [child({'success': True, 'result': {'selected': True, 'changed': changed}})]
    if changed:
        responses.append(subprocess.CompletedProcess([], 0, b'GUI started', b''))
    run = mock.Mock(side_effect=responses)
    backend = NativeGuiBackend(None, run=run)
    with mock.patch('certificate_backend.os.geteuid', return_value=0, create=True):
        assert backend.install(IDENTITY) is True
    assert run.call_count == (2 if changed else 1)
    if changed:
        assert run.call_args.args[0] == ['/usr/local/etc/rc.restart_webgui']
        assert run.call_args.kwargs['timeout'] == 8
    body = json.loads(run.call_args_list[0].kwargs['input'])
    assert body == {'action': 'install', 'request': IDENTITY}


@pytest.mark.parametrize('reply', [b'private malformed reply', b'x' * 16385,
                                 json.dumps({'success': True, 'result': {'selected': True, 'private_key': 'never return'}}).encode()])
def test_native_child_diagnostics_or_extra_fields_never_become_a_public_error(reply):
    run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, reply, b'private child diagnostic'))
    backend = NativeGuiBackend(None, run=run)
    with mock.patch('certificate_backend.os.geteuid', return_value=0, create=True):
        with pytest.raises(NativeGuiError) as error:
            backend.check(IDENTITY)
    assert str(error.value) == 'Native GUI certificate operation failed'


def test_only_known_static_native_prerequisites_cross_the_boundary():
    run = mock.Mock(return_value=child({'success': False, 'code': 'alternate_hostname_required', 'message': 'private diagnostic'}, 1))
    backend = NativeGuiBackend(None, run=run)
    with mock.patch('certificate_backend.os.geteuid', return_value=0, create=True):
        with pytest.raises(CertificatePreparationRequired) as error:
            backend.prepare('a' * 32, 'b' * 64, None)
    assert error.value.code == 'alternate_hostname_required' and 'private' not in str(error.value)


def test_normal_rollback_restarts_after_an_uncertain_previous_restart():
    run = mock.Mock(side_effect=[child({'success': True, 'result': {'restored': True, 'changed': False}}),
                                 subprocess.CompletedProcess([], 0, b'GUI restarted', b'')])
    backend = NativeGuiBackend(None, run=run)
    with mock.patch('certificate_backend.os.geteuid', return_value=0, create=True):
        assert backend.rollback(IDENTITY) is True
    assert run.call_args.args[0] == ['/usr/local/etc/rc.restart_webgui']


def test_boot_rollback_confirms_a_native_save_with_a_lost_reply_without_restart():
    run = mock.Mock(side_effect=[subprocess.CompletedProcess([], 1, b'private truncated reply', b''),
                                 child({'success': True, 'result': {'restored': True, 'changed': False}})])
    backend = NativeGuiBackend(None, boot=True, run=run)
    with mock.patch('certificate_backend.os.geteuid', return_value=0, create=True):
        assert backend.rollback(IDENTITY) is True
    assert run.call_count == 2
    assert all(call.args[0][0] == '/usr/local/bin/php' for call in run.call_args_list)


@contextlib.contextmanager
def tls_server(case, message, status=200):
    path = case.root / 'served-public-chain.pem'
    path.write_text(message['issued']['chain_pem'])
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(path, case.key.directory / 'key.pem')
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(2)
    listener.settimeout(5)
    requests = []

    def serve():
        try:
            raw, _ = listener.accept()
            raw.settimeout(3)
            with raw:
                with server.wrap_socket(raw, server_side=True) as peer:
                    value = b''
                    while b'\r\n\r\n' not in value and len(value) <= 4096:
                        piece = peer.recv(4096)
                        if not piece:
                            return
                        value += piece
                    requests.append(value)
                    peer.sendall(('HTTP/1.1 ' + str(status) + ' Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n').encode())
        except (OSError, ssl.SSLError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], requests
    finally:
        listener.close()
        thread.join(6)
        assert not thread.is_alive(), 'Private TLS fixture did not stop'


@pytest.mark.parametrize('failure', [None, 'comments', 'fingerprint', 'untrusted', 'hostname', 'http'])
def test_probe_requires_independent_chain_hostname_fingerprint_and_http(chain, failure):
    message = chain.issue()
    root = chain.ca
    if failure == 'comments':
        root.write_bytes(b'# Independent roots: caf\xc3\xa9\n' + root.read_bytes())
    if failure == 'untrusted':
        root = chain.root / 'another-independent-root.pem'
        chain.command('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
                      '-days', '2', '-subj', '/CN=Unrelated TLS probe root', '-keyout', chain.root / 'other-private.pem',
                      '-out', root, '-addext', 'basicConstraints=critical,CA:TRUE')
    backend = NativeGuiBackend(chain.key, root)
    with tls_server(chain, message, status=503 if failure == 'http' else 200) as (port, requests):
        metadata = {'selected': True, 'host': 'ijklmnop.devices.example.test' if failure == 'hostname' else HOST,
                    'port': port, 'leaf_fingerprint': 'f' * 64 if failure == 'fingerprint' else message['issued']['leaf_fingerprint']}
        with mock.patch.object(backend, '_call', return_value=metadata):
            assert backend.probe(dict(IDENTITY, port=port)) is (failure in (None, 'comments'))
        if failure in (None, 'comments'):
            assert requests and requests[0].startswith(('HEAD / HTTP/1.1\r\nHost: ' + HOST + ':' + str(port)).encode())
            assert b'Authorization' not in requests[0] and b'Cookie' not in requests[0]
