"""Run the actual PHP store against marked temporary XML, never host config."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

import pytest

from test_certificate_chain import chain, DEVICE, HOST
from certificate_key import KeyStore
from certificate_transaction import CertificateTransaction, CertificateTransactionError

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Native PHP filesystem contracts require POSIX ownership')
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'src/usr/local/opnsense/scripts/nethub-agent/gui_certificate_store.php'
PROGRAM = ROOT / 'tests/gui_certificate_store_contract.php'


class NativeStoreContractError(Exception):
    """A fixed diagnostic; the native model never prints private snapshots."""


class PhpModel:
    def __init__(self, parent):
        self.parent = parent
        self.directory = parent / 'gui-apply'
        self.configuration = parent / 'native-config.xml'
        self.state = parent / 'state'
        self.state.mkdir(mode=0o700)
        (parent / 'fenced-native-store-fixture').write_text('fixture-only')
        self.healthy = True
        self.last_response = {}
        self.operations = []

    def call(self, action, request):
        value = {'config_file': str(self.configuration), 'directory': str(self.directory),
                 'state_directory': str(self.state), 'owner': os.geteuid(), 'action': action, 'request': request}
        php = os.environ.get('NETHUB_TEST_PHP') or shutil.which('php')
        assert php, 'Native PHP with DOM, SimpleXML and OpenSSL is required'
        result = subprocess.run([php, str(PROGRAM), str(SCRIPT)], input=json.dumps(value).encode(), capture_output=True, timeout=8)
        assert len(result.stdout) <= 16384, 'Native fixture returned an oversized response'
        try:
            response = json.loads(result.stdout)
        except ValueError:
            raise NativeStoreContractError('Native fixture did not return a bounded response') from None
        self.last_response = response
        if result.returncode or response.get('success') is not True:
            raise NativeStoreContractError('Native fixture refused the operation')
        self.operations.append(action)
        return response['result']

    def prepare(self, nonce, digest, good):
        return self.call('prepare', {'nonce': nonce, 'candidate_sha256': digest, 'last_good': good})

    @staticmethod
    def identity(value):
        return {key: value[key] for key in ('nonce', 'snapshot_sha256', 'candidate_sha256')}

    def install(self, value):
        return self.call('install', self.identity(value))['selected'] is True

    def check(self, value):
        return self.call('check', self.identity(value))['selected'] is True

    def rollback(self, value):
        return self.call('rollback', self.identity(value))['restored'] is True

    def probe(self, value):
        # This is deliberately a model probe, not a native TLS/GUI acceptance.
        return self.healthy

    def unrelated(self):
        root = ET.parse(self.configuration).getroot()
        root.find('system/webgui/ssl-certref').text = 'original'
        for node in list(root.findall('cert')):
            if node.findtext('descr', '').startswith('NetHub managed GUI '):
                root.remove(node)
        for node in root.iter():
            if node.text is not None and not node.text.strip():
                node.text = None
            if node.tail is not None and not node.tail.strip():
                node.tail = None
        return hashlib.sha256(ET.tostring(root)).hexdigest()


@pytest.fixture
def store(chain):
    parent = (chain.root / 'native-model').resolve()
    parent.mkdir(mode=0o700)
    backend = PhpModel(parent)
    key = parent / 'gui-key'
    key.mkdir(mode=0o700)
    (key / 'key.pem').write_bytes((chain.key.directory / 'key.pem').read_bytes())
    (key / 'key.pem').chmod(0o600)
    value = chain.verify.verify(chain.issue(), DEVICE, HOST.split('.')[0], chain.original)
    (parent / 'gui-certificate.json').write_bytes(KeyStore._encoded(value))
    (parent / 'gui-certificate.json').chmod(0o600)
    root = ET.fromstring('<opnsense><system><ssh>retain</ssh><webgui><protocol>https</protocol>'
                         '<ssl-certref>original</ssl-certref><port>443</port><protection>retain</protection></webgui></system>'
                         '<OPNsense><NetHubAgent><enabled>1</enabled></NetHubAgent><Unrelated>retain</Unrelated></OPNsense>'
                         '<cert><refid>original</refid><descr>Original native GUI</descr><crt>fixture-public</crt>'
                         '<prv>independent original native fixture</prv></cert></opnsense>')
    model = root.find('OPNsense/NetHubAgent')
    ET.SubElement(model, 'device_id').text = DEVICE
    ET.SubElement(model, 'subdomain').text = HOST.split('.')[0]
    ET.SubElement(root.find('system/webgui'), 'althostnames').text = HOST
    ET.ElementTree(root).write(backend.configuration)
    backend.configuration.chmod(0o600)
    clock = [1800000000]
    journal = CertificateTransaction(backend.directory, backend, clock=lambda: clock[0])
    return journal, backend, value, chain, clock


def apply(journal, backend, value):
    try:
        return journal.apply(value)
    except CertificateTransactionError:
        response = backend.last_response
        pytest.fail('Native model refused application: ' + str(response.get('error_type')) +
                    ' at line ' + str(response.get('error_line')), pytrace=False)


def test_actual_php_import_is_scoped_and_private_snapshot_never_reaches_stdout(store):
    journal, backend, value, chain, _ = store
    before = backend.unrelated()
    assert apply(journal, backend, value)['phase'] == 'applied'
    record = json.loads(journal.path.read_bytes())
    root = ET.parse(backend.configuration).getroot()
    assert root.findtext('system/webgui/ssl-certref') == record['refid']
    owned = [node for node in root.findall('cert') if node.findtext('refid') == record['refid']]
    assert len(owned) == 1
    assert hashlib.sha256(base64.b64decode(owned[0].findtext('crt'))).hexdigest() == hashlib.sha256(value['issued']['chain_pem'].encode()).hexdigest()
    assert backend.unrelated() == before
    snapshot = journal.directory / ('snapshot-' + record['nonce'] + '.json')
    assert snapshot.stat().st_mode & 0o777 == 0o600
    private_copy = base64.b64encode((chain.key.directory / 'key.pem').read_bytes())
    retained_locally = private_copy in snapshot.read_bytes()
    exposed_in_response = private_copy in json.dumps(backend.last_response).encode()
    assert retained_locally and not exposed_in_response
    assert apply(journal, backend, value)['phase'] == 'applied'
    assert backend.operations.count('install') == 1


def test_actual_php_first_install_rollback_removes_only_its_owned_entry(store):
    journal, backend, value, _, _ = store
    baseline = backend.configuration.read_bytes()
    digest = backend.unrelated()
    backend.healthy = False
    with pytest.raises(CertificateTransactionError):
        journal.apply(value)
    root = ET.parse(backend.configuration).getroot()
    assert root.findtext('system/webgui/ssl-certref') == 'original' and len(root.findall('cert')) == 1
    assert backend.unrelated() == digest and journal.recover() is None
    assert ET.tostring(ET.fromstring(baseline)) == ET.tostring(root)


def test_actual_php_primary_native_hostname_needs_no_redundant_alias_or_security_change(store):
    journal, backend, value, _, _ = store
    root = ET.parse(backend.configuration)
    gui = root.find('system/webgui')
    gui.remove(gui.find('althostnames'))
    system = root.find('system')
    ET.SubElement(system, 'hostname').text = HOST.split('.')[0]
    ET.SubElement(system, 'domain').text = HOST.split('.', 1)[1]
    root.write(backend.configuration)
    before = backend.unrelated()
    assert apply(journal, backend, value)['phase'] == 'applied'
    assert backend.unrelated() == before
    current = ET.parse(backend.configuration)
    assert current.find('system/webgui/althostnames') is None
    assert current.find('system/webgui/nodnsrebindcheck') is None
    assert current.find('system/webgui/nohttpreferercheck') is None


def test_actual_php_renewal_failure_restores_the_previous_owned_native_certificate(store):
    journal, backend, value, chain, _ = store
    apply(journal, backend, value)
    before = hashlib.sha256(backend.configuration.read_bytes()).hexdigest()
    newer = chain.issue()
    newer['issued']['generation'] = 2
    newer['issued']['generation_id'] = '456789ab-4567-4567-4567-456789abcdef'
    (backend.parent / 'gui-certificate.json').write_bytes(KeyStore._encoded(newer))
    backend.healthy = False
    with pytest.raises(CertificateTransactionError):
        journal.apply(newer)
    assert hashlib.sha256(backend.configuration.read_bytes()).hexdigest() == before
    assert json.loads(journal.path.read_bytes())['phase'] == 'rolled_back'


@pytest.mark.parametrize('fault', ['disabled', 'revoked', 'wrong_key', 'duplicate_reference', 'manual_hostname_missing'])
def test_actual_php_preparation_refuses_changed_identity_or_intent_before_native_write(store, fault):
    journal, backend, value, chain, _ = store
    if fault == 'disabled':
        root = ET.parse(backend.configuration)
        root.find('OPNsense/NetHubAgent/enabled').text = '0'
        root.write(backend.configuration)
    elif fault == 'revoked':
        (backend.state / 'revoked').touch()
    elif fault == 'wrong_key':
        different = KeyStore(chain.root / 'another-runtime-key', chain.key.openssl)
        different.ensure()
        (backend.parent / 'gui-key/key.pem').write_bytes((different.directory / 'key.pem').read_bytes())
    elif fault == 'duplicate_reference':
        root = ET.parse(backend.configuration)
        root.getroot().append(copy.deepcopy(root.find('cert')))
        root.write(backend.configuration)
    else:
        root = ET.parse(backend.configuration)
        gui = root.find('system/webgui')
        gui.remove(gui.find('althostnames'))
        root.write(backend.configuration)
    before = backend.configuration.read_bytes()
    with pytest.raises(CertificateTransactionError):
        journal.apply(value)
    assert backend.configuration.read_bytes() == before and not journal.path.exists()
    assert 'install' not in backend.operations
    if fault == 'manual_hostname_missing':
        assert backend.last_response['error_type'] == 'NativeGuiCertificatePrerequisite'


@pytest.mark.parametrize('change', ['selected_ref', 'owned_description'])
def test_actual_php_does_not_replace_an_operator_changed_applied_selection(store, change):
    journal, backend, value, _, _ = store
    apply(journal, backend, value)
    root = ET.parse(backend.configuration)
    if change == 'selected_ref':
        root.find('system/webgui/ssl-certref').text = 'original'
    else:
        ref = root.findtext('system/webgui/ssl-certref')
        for node in root.findall('cert'):
            if node.findtext('refid') == ref:
                node.find('descr').text = 'Operator changed this entry'
    root.write(backend.configuration)
    before = backend.configuration.read_bytes()
    with pytest.raises(CertificateTransactionError):
        journal.apply(value)
    assert backend.configuration.read_bytes() == before
    assert json.loads(journal.path.read_bytes())['phase'] == 'applied'


def test_actual_php_rollback_refuses_an_operator_changed_original_certificate(store):
    journal, backend, value, _, _ = store
    captured = []

    def operator_change(record):
        root = ET.parse(backend.configuration)
        root.find('cert/descr').text = 'Operator changed the original certificate'
        root.write(backend.configuration)
        captured.append(backend.configuration.read_bytes())
        return False

    backend.probe = operator_change
    with pytest.raises(CertificateTransactionError, match='local recovery'):
        journal.apply(value)
    assert captured and backend.configuration.read_bytes() == captured[0]
    assert json.loads(journal.path.read_bytes())['phase'] == 'written'


@pytest.mark.parametrize('body', [b'not-json', b'x' * 16385,
                                 b'{"action":"read_all_config","request":{}}',
                                 b'{"action":"check","request":{"unexpected":"private-test-value"}}'])
def test_private_cli_rejects_malformed_input_before_native_bootstrap(body):
    php = os.environ.get('NETHUB_TEST_PHP') or shutil.which('php')
    assert php, 'Native PHP is required'
    # Every case fails before load_phalcon.php or Config::getInstance is reached.
    result = subprocess.run([php, str(SCRIPT.with_name('gui_certificate.php'))], input=body,
                            capture_output=True, timeout=5)
    assert result.returncode == 1 and len(result.stdout) <= 2048
    value = json.loads(result.stdout)
    assert value['success'] is False and 'private-test-value' not in json.dumps(value)
