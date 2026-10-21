"""Check key-before-network enrollment and shared-lock removal boundaries."""
import json
import subprocess
from unittest import mock
import xml.etree.ElementTree as ET

import pytest
import test_reconcile as base
from certificate_key import CertificateKeyError, KeyStore
from protocol import ProtocolError


@pytest.fixture
def case():
    fixture = base.ReconcileTests()
    fixture.setUp()
    try:
        product = fixture.root / 'usr/local/opnsense/version/nethub-agent'
        product.parent.mkdir(parents=True)
        product.write_text(json.dumps({'product_version':'0.0.6'}))
        fixture.agent.state.mkdir(parents=True)
        old = fixture.agent.run
        def command(args, **kwargs):
            if str(args[0]) == '/usr/local/sbin/opnsense-version':
                return subprocess.CompletedProcess(args, 0, '26.7.7', '')
            return old(args, **kwargs)
        fixture.agent.run = command
        yield fixture
    finally:
        fixture.doCleanups()


def request_file(case):
    directory = case.agent.state / 'requests'
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / ('enroll-'+'a'*32+'.json')
    path.write_text(json.dumps({'origin':'https://console.example.test','token':'A'*43}))
    path.chmod(0o600)
    return path


def test_fresh_enrollment_persists_key_before_request_and_retains_it_on_retry(case):
    original = (case.root / 'conf/config.xml').read_bytes()
    public = []
    private_bytes = []
    def unavailable(*args, **kwargs):
        value = KeyStore(case.agent.config / 'gui-key').ensure()
        assert kwargs['gui_public_key'] == value['public_key']
        public.append(value['public_key'])
        private_bytes.append((case.agent.config / 'gui-key/key.pem').read_bytes())
        raise ProtocolError('Server did not confirm the certificate key binding')
    with mock.patch('enrollment.request_enrollment', side_effect=unavailable) as network:
        for _ in range(2):
            result = case.agent.enroll(request_file(case))
            assert result['success'] is False
            assert result['message'] == 'Server did not confirm the certificate key binding'
    assert network.call_count == 2 and public[0] == public[1] and private_bytes[0] == private_bytes[1]
    assert 'PRIVATE KEY' not in json.dumps(result)
    assert (case.root / 'conf/config.xml').read_bytes() == original


def test_key_failure_stops_before_network(case):
    with mock.patch('certificate_key.KeyStore.ensure', side_effect=CertificateKeyError('Certificate key storage needs local review')):
        with mock.patch('enrollment.request_enrollment') as network:
            result = case.agent.enroll(request_file(case))
    assert result == {'success':False,'message':'Certificate key storage needs local review'}
    network.assert_not_called()


def test_enrolled_legacy_device_does_not_generate_or_backfill_a_key(case):
    tree = ET.parse(case.root / 'conf/config.xml')
    ET.SubElement(tree.find('OPNsense/NetHubAgent'), 'device_id').text = 'existing'
    tree.write(case.root / 'conf/config.xml')
    with mock.patch('certificate_key.KeyStore.ensure') as key:
        with mock.patch('enrollment.request_enrollment') as network:
            assert case.agent.enroll(request_file(case)) == {'success':True,'enrolled':True}
    key.assert_not_called()
    network.assert_not_called()


def test_enrollment_uses_common_mutation_lock_before_consuming_request(case):
    path = request_file(case)
    with (case.agent.state / 'reconcile.lock').open('a') as lock:
        base.MODULE.fcntl.flock(lock, base.MODULE.fcntl.LOCK_EX | base.MODULE.fcntl.LOCK_NB)
        result = case.agent.enroll(path)
    assert result['action'] == 'busy' and path.exists()
    assert not (case.agent.config / 'gui-key').exists()


def test_runtime_key_removal_requires_cleared_fields_and_preserves_native_certificate(case):
    key = KeyStore(case.agent.config / 'gui-key')
    # The config directory is protected by Agent.apply in normal use.
    case.agent.config.chmod(0o700)
    key.ensure()
    original_key = (key.directory / 'key.pem').read_bytes()
    result = case.agent.apply('forget')
    assert result['success'] is False and (key.directory / 'key.pem').read_bytes() == original_key
    case.set_enabled(False)
    original = (case.root / 'conf/config.xml').read_bytes()
    native = case.root / 'conf/native-certificate-fixture'
    native.write_text('native certificate store is independent')
    result = case.agent.apply('forget')
    assert result['success'] is True and not key.directory.exists()
    assert (case.root / 'conf/config.xml').read_bytes() == original
    assert native.read_text() == 'native certificate store is independent'
    assert case.agent.apply('forget')['success'] is True


@pytest.mark.parametrize('name', ['gui-apply', 'gui-request', 'gui-certificate.json'])
def test_reenrollment_waits_for_incomplete_former_runtime_cleanup(case, name):
    path = request_file(case)
    remnant = case.agent.config / name
    if name.endswith('.json'):
        remnant.write_text('Retain until removal cleanup')
    else:
        remnant.mkdir(mode=0o700)
    with mock.patch('enrollment.request_enrollment') as network, mock.patch.object(KeyStore, 'ensure') as key:
        result = case.agent.enroll(path)
    assert result['success'] is False and 'cleanup is incomplete' in result['message']
    network.assert_not_called()
    key.assert_not_called()
    assert remnant.exists()
