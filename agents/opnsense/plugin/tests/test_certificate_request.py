"""Exercise real signed requests, durable reuse and fail-closed cache recovery."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/nethub-agent'))
from certificate_key import KeyStore
from certificate_request import CertificateRequestError, RequestStore


@pytest.fixture
def store(tmp_path):
    tmp_path.chmod(0o700)
    openssl = shutil.which('openssl')
    assert openssl, 'The appliance base OpenSSL or test equivalent is required'
    key = KeyStore(tmp_path / 'key', openssl)
    identity = key.ensure()
    return RequestStore(tmp_path / 'request', key), identity


HOST = 'abcdefgh.devices.example.test'


def ensure(store, identity, host=HOST):
    return store.ensure(host, identity['fingerprint'])


def test_actual_signature_profile_and_exact_reuse(store):
    request, identity = store
    pem = ensure(request, identity)
    command = [request.key_store.openssl, 'req', '-verify', '-noout', '-text']
    child = subprocess.run(command, input=pem, capture_output=True)
    assert child.returncode == 0
    assert b'DNS:' + HOST.encode() in child.stdout
    assert b'ecdsa-with-SHA256' in child.stdout
    before = (request.directory / 'request.json').read_bytes()
    with mock.patch.object(request, '_command', wraps=request._command) as run:
        assert RequestStore(request.directory, request.key_store).ensure(HOST, identity['fingerprint']) == pem
        assert ensure(request, identity) == pem
    assert all('dgst' not in call.args[0] for call in run.call_args_list)
    assert (request.directory / 'request.json').read_bytes() == before
    if os.name != 'nt':
        assert request.directory.stat().st_mode & 0o777 == 0o700
        assert (request.directory / 'request.json').stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('host', ['*.devices.example.test', 'HOST.example.test', 'example.test.',
                                 '127.0.0.1', 'a/b.example.test', 'a\n.example.test',
                                 'a' * 64 + '.example.test', 'localhost', '-bad.example.test'])
def test_invalid_identity_cannot_sign_or_create_storage(store, host):
    request, identity = store
    with mock.patch.object(request, '_command') as run:
        with pytest.raises(CertificateRequestError):
            ensure(request, identity, host)
    run.assert_not_called()
    assert not request.directory.exists()


def test_wrong_binding_and_changed_assignment_preserve_request(store):
    request, identity = store
    original = ensure(request, identity)
    before = (request.directory / 'request.json').read_bytes()
    for host, fingerprint in [(HOST, 'f' * 64), ('ijklmnop.devices.example.test', identity['fingerprint'])]:
        with pytest.raises(CertificateRequestError):
            request.ensure(host, fingerprint)
    assert ensure(request, identity) == original
    assert (request.directory / 'request.json').read_bytes() == before


@pytest.mark.parametrize('mutation', ['host', 'fingerprint', 'signature', 'duplicate', 'noncanonical', 'extra'])
def test_corrupt_cache_is_never_replaced(store, mutation):
    request, identity = store
    ensure(request, identity)
    path = request.directory / 'request.json'
    value = json.loads(path.read_bytes())
    if mutation == 'host':
        value['host'] = 'ijklmnop.devices.example.test'
    elif mutation == 'fingerprint':
        value['key_fingerprint'] = 'f' * 64
    elif mutation == 'signature':
        raw = bytearray(base64.b64decode(value['csr']))
        raw[-1] ^= 1
        value['csr'] = base64.b64encode(raw).decode()
    elif mutation == 'extra':
        value['unexpected'] = True
    raw = request._encoded(value)
    if mutation == 'duplicate':
        raw = raw[:-2] + b',"version":1}\n'
    if mutation == 'noncanonical':
        raw += b'\n'
    path.write_bytes(raw)
    with pytest.raises(CertificateRequestError):
        ensure(request, identity)
    assert path.read_bytes() == raw


def test_missing_bound_key_cannot_generate_new_identity(store):
    request, identity = store
    (request.key_store.directory / 'key.pem').unlink()
    with pytest.raises(CertificateRequestError):
        ensure(request, identity)
    assert not request.directory.exists()
    assert not (request.key_store.directory / 'key.pem').exists()


def test_valid_signature_for_another_identity_is_rejected(store):
    request, identity = store
    ensure(request, identity)
    original = request.directory / 'request.json'
    value = json.loads(original.read_bytes())
    other = RequestStore(request.directory.parent / 'other', request.key_store)
    other.ensure('ijklmnop.devices.example.test', identity['fingerprint'])
    value['csr'] = json.loads((other.directory / 'request.json').read_bytes())['csr']
    raw = request._encoded(value)
    original.write_bytes(raw)
    with pytest.raises(CertificateRequestError):
        ensure(request, identity)
    assert original.read_bytes() == raw


def test_maximum_dns_name_uses_the_same_restricted_profile(store):
    request, identity = store
    host = '.'.join(['a' * 63, 'b' * 63, 'c' * 63, 'd' * 61])
    assert len(host) == 253
    pem = ensure(request, identity, host)
    assert ensure(request, identity, host) == pem


def test_signer_failure_hides_output_and_does_not_publish(store):
    request, identity = store
    original = subprocess.run
    def fail(args, **kwargs):
        if 'dgst' in args:
            return subprocess.CompletedProcess(args, 1, b'private child output', b'private diagnostic')
        return original(args, **kwargs)
    with mock.patch('certificate_request.subprocess.run', side_effect=fail):
        with pytest.raises(CertificateRequestError) as error:
            ensure(request, identity)
    assert str(error.value) == 'Could not validate the device certificate request'
    assert not request.directory.exists()
    assert not list(request.directory.parent.glob('.gui-csr-*'))


def test_zero_exit_does_not_turn_a_failed_signature_check_into_success(store):
    request, identity = store
    original = subprocess.run
    def rejected(args, **kwargs):
        if 'req' in args:
            return subprocess.CompletedProcess(args, 0, b'', b'Certificate request self-signature verify failure\n')
        return original(args, **kwargs)
    with mock.patch('certificate_request.subprocess.run', side_effect=rejected):
        with pytest.raises(CertificateRequestError):
            ensure(request, identity)
    assert not request.directory.exists()
    assert not list(request.directory.parent.glob('.gui-csr-*'))


def test_interrupted_publication_reuses_committed_request(store):
    request, identity = store
    original_sync = request.key_store._sync
    def fail_parent(path):
        if path == request.directory.parent:
            raise OSError('Child diagnostic must not escape')
        return original_sync(path)
    with mock.patch.object(request.key_store, '_sync', side_effect=fail_parent):
        with pytest.raises(CertificateRequestError, match='needs local review'):
            ensure(request, identity)
    saved = (request.directory / 'request.json').read_bytes()
    assert ensure(request, identity)
    assert (request.directory / 'request.json').read_bytes() == saved


def test_failure_before_publication_leaves_no_partial_request(store):
    request, identity = store
    with mock.patch('certificate_request.os.fsync', side_effect=OSError('private diagnostic')):
        with pytest.raises(CertificateRequestError) as error:
            ensure(request, identity)
    assert str(error.value) == 'Device certificate request needs local review'
    assert not request.directory.exists()
    assert not list(request.directory.parent.glob('.gui-csr-*'))


@pytest.mark.skipif(os.name == 'nt', reason='Production ownership and link checks require POSIX')
@pytest.mark.parametrize('mutation', ['mode', 'link', 'unknown'])
def test_unsafe_request_storage_is_preserved(store, mutation):
    request, identity = store
    ensure(request, identity)
    path = request.directory / 'request.json'
    if mutation == 'mode':
        path.chmod(0o644)
    elif mutation == 'link':
        saved = request.directory.parent / 'saved.json'
        path.rename(saved)
        path.symlink_to(saved)
    else:
        (request.directory / 'unknown').write_text('preserve')
    before = path.read_bytes()
    with pytest.raises(CertificateRequestError):
        ensure(request, identity)
    assert path.read_bytes() == before
