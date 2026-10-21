"""Exercise real native OpenSSL trust and exact enrolled-key/SAN checks."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/nethub-agent'))
from certificate_chain import CertificateChainError, ChainVerifier
from certificate_key import KeyStore
from certificate_request import RequestStore
from protocol import VERSION

HOST = 'abcdefgh.devices.example.test'
DEVICE = '12345678-1234-1234-1234-123456789abc'
LAYOUT = '%Y-%m-%dT%H:%M:%S.%fZ'


@pytest.fixture
def chain(tmp_path):
    tmp_path.chmod(0o700)
    binary = shutil.which('openssl')
    assert binary, 'Native OpenSSL or its test equivalent is required'

    def command(*args):
        result = subprocess.run([binary, *map(str, args)], capture_output=True, timeout=5)
        assert result.returncode == 0, 'Private certificate fixture construction failed'
        return result.stdout

    key = KeyStore(tmp_path / 'key', binary)
    identity = key.ensure()
    requests = RequestStore(tmp_path / 'request', key)
    csr = requests.ensure(HOST, identity['fingerprint'])
    request = json.loads((requests.directory / 'request.json').read_text())
    der = base64.b64decode(request['csr'], validate=True)
    original = dict(request_id='23456789-2345-2345-2345-23456789abcd', csr_der=request['csr'],
                    csr_fingerprint=hashlib.sha256(der).hexdigest(), created_at=datetime.now(timezone.utc).strftime(LAYOUT))
    csr_file = tmp_path / 'public.csr'
    csr_file.write_bytes(csr)
    ca, ca_key = tmp_path / 'root.pem', tmp_path / 'root-key.pem'
    command('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
            '-days', '2', '-subj', '/CN=Private certificate fixture root', '-keyout', ca_key, '-out', ca,
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')

    def issue(changes=None, remove=(), days=1):
        profile = {'basicConstraints': 'critical,CA:FALSE', 'keyUsage': 'critical,digitalSignature',
                   'extendedKeyUsage': 'serverAuth', 'subjectAltName': 'DNS:' + HOST}
        profile.update(changes or {})
        for name in remove:
            profile.pop(name)
        extensions = tmp_path / 'extensions.txt'
        extensions.write_text(''.join(name + '=' + value + '\n' for name, value in profile.items()))
        leaf = tmp_path / 'leaf.pem'
        command('x509', '-req', '-in', csr_file, '-CA', ca, '-CAkey', ca_key, '-set_serial', '2',
                '-days', str(days), '-extfile', extensions, '-out', leaf)
        dates = command('x509', '-in', leaf, '-noout', '-dates').decode('ascii').splitlines()
        parsed = {line.split('=', 1)[0]: datetime.fromtimestamp(ssl.cert_time_to_seconds(line.split('=', 1)[1]), timezone.utc) for line in dates}
        leaf_der = command('x509', '-in', leaf, '-outform', 'DER')
        issued = dict(generation_id='3456789a-3456-3456-3456-3456789abcde', generation=1,
                      chain_pem=leaf.read_text(), leaf_fingerprint=hashlib.sha256(leaf_der).hexdigest(),
                      not_before=parsed['notBefore'].strftime(LAYOUT), not_after=parsed['notAfter'].strftime(LAYOUT),
                      valid_until=parsed['notAfter'].strftime(LAYOUT),
                      renew_after=(parsed['notBefore'] + timedelta(hours=8)).strftime(LAYOUT))
        return dict(agent_protocol_version=VERSION, device_id=DEVICE, assigned_host=HOST,
                    gui_key_fingerprint=identity['fingerprint'], request=copy.deepcopy(original), issued=issued)

    return SimpleNamespace(root=tmp_path, key=key, original=original, issue=issue, ca=ca,
                           verify=ChainVerifier(key, ca), command=command)


def verify(case, message):
    return case.verify.verify(message, DEVICE, HOST.split('.')[0], case.original)


def test_native_verified_delivery_keeps_key_and_removes_public_scratch(chain):
    message = chain.issue()
    before = {p.name: p.read_bytes() for p in chain.key.directory.iterdir()}
    assert verify(chain, message) == message
    assert verify(chain, message) == message
    assert before == {p.name: p.read_bytes() for p in chain.key.directory.iterdir()}
    assert not list(chain.root.glob('.gui-chain-*'))
    pending = dict(message, issued=None)
    assert verify(chain, pending)['issued'] is None


def test_server_root_is_never_its_own_trusted_anchor(chain):
    message = chain.issue()
    message['issued']['chain_pem'] += chain.ca.read_text()
    assert verify(chain, message) == message
    with pytest.raises(CertificateChainError):
        ChainVerifier(chain.key).verify(message, DEVICE, HOST.split('.')[0], chain.original)
    wrong = chain.root / 'unrelated-root.pem'
    chain.command('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
                  '-days', '2', '-subj', '/CN=Unrelated private root', '-keyout', chain.root / 'unrelated-key.pem', '-out', wrong,
                  '-addext', 'basicConstraints=critical,CA:TRUE')
    with pytest.raises(CertificateChainError):
        ChainVerifier(chain.key, wrong).verify(message, DEVICE, HOST.split('.')[0], chain.original)
    message['issued']['chain_pem'] += wrong.read_text()
    with pytest.raises(CertificateChainError):
        verify(chain, message)
    assert not list(chain.root.glob('.gui-chain-*'))


def test_environment_cannot_replace_native_trust_with_the_response_root(chain):
    message = chain.issue()
    with mock.patch.dict(os.environ, {'SSL_CERT_FILE': str(chain.ca), 'SSL_CERT_DIR': str(chain.root)}):
        with pytest.raises(CertificateChainError):
            ChainVerifier(chain.key).verify(message, DEVICE, HOST.split('.')[0], chain.original)


def test_repeated_response_certificate_is_refused(chain):
    message = chain.issue()
    message['issued']['chain_pem'] += chain.ca.read_text() * 2
    with pytest.raises(CertificateChainError):
        verify(chain, message)


@pytest.mark.parametrize('changes,remove', [
    ({'subjectAltName': 'DNS:wrong.devices.example.test'}, ()),
    ({'subjectAltName': 'DNS:' + HOST + ',DNS:extra.devices.example.test'}, ()),
    ({'subjectAltName': 'DNS:' + HOST + ',URI:https://extra.example.test'}, ()),
    ({'basicConstraints': 'critical,CA:TRUE'}, ()),
    ({}, ('basicConstraints',)),
    ({'keyUsage': 'critical,keyEncipherment'}, ()),
    ({}, ('keyUsage',)),
    ({'extendedKeyUsage': 'clientAuth'}, ()),
    ({}, ('extendedKeyUsage',)),
    ({'1.2.3.4': 'critical,DER:01:01:ff'}, ()),
])
def test_native_profile_rejects_trusted_but_wrong_leaf(chain, changes, remove):
    message = chain.issue(changes, remove)
    with pytest.raises(CertificateChainError, match='^GUI certificate verification failed; enrolled key and configuration were retained$'):
        verify(chain, message)
    assert not list(chain.root.glob('.gui-chain-*'))


def test_native_checks_signed_times_and_signature_beyond_wire_integrity(chain):
    message = chain.issue()
    wrong_time = copy.deepcopy(message)
    wrong_time['issued']['not_before'] = '2026-01-01T00:00:00.000000Z'
    with pytest.raises(CertificateChainError):
        verify(chain, wrong_time)
    raw = base64.b64decode(''.join(message['issued']['chain_pem'].splitlines()[1:-1]), validate=True)
    raw = raw[:-1] + bytes([raw[-1] ^ 1])
    encoded = base64.b64encode(raw).decode('ascii')
    message['issued']['chain_pem'] = '-----BEGIN CERTIFICATE-----\n' + ''.join(encoded[i:i+64] + '\n' for i in range(0, len(encoded), 64)) + '-----END CERTIFICATE-----\n'
    message['issued']['leaf_fingerprint'] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(CertificateChainError):
        verify(chain, message)


def test_missing_enrolled_key_never_creates_a_replacement(chain):
    message = chain.issue()
    (chain.key.directory / 'key.pem').unlink()
    with pytest.raises(CertificateChainError):
        verify(chain, message)
    assert not (chain.key.directory / 'key.pem').exists()


def test_effective_lifetime_cannot_outlive_independent_omitted_root(chain):
    message = chain.issue(days=3)
    with pytest.raises(CertificateChainError):
        verify(chain, message)
    text = chain.command('x509', '-in', chain.ca, '-noout', '-enddate').decode('ascii').strip().split('=', 1)[1]
    until = datetime.fromtimestamp(ssl.cert_time_to_seconds(text), timezone.utc)
    message['issued']['valid_until'] = until.strftime(LAYOUT)
    assert verify(chain, message) == message


def test_unprotected_or_private_root_input_is_refused(chain):
    message = chain.issue()
    with pytest.raises(CertificateChainError):
        ChainVerifier(chain.key, chain.root / 'root-key.pem').verify(message, DEVICE, HOST.split('.')[0], chain.original)
    if hasattr(os, 'geteuid'):
        chain.ca.chmod(0o666)
        with pytest.raises(CertificateChainError):
            verify(chain, message)


def test_zero_exit_without_exact_native_positive_result_is_refused(chain):
    with mock.patch('certificate_chain.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=b'verification failed', stderr=b'')):
        with pytest.raises(ValueError):
            chain.verify._verify(['verify'], b'leaf.pem: OK')
