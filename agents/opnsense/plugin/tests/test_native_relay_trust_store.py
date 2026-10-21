"""Exercise the real PHP CAS writer against marked temporary native XML."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src/usr/local/opnsense/scripts/nethub-agent'))
from relay_trust_backend import NativeTrustBackend, model_nodes
from relay_trust_transaction import TrustTransaction, TrustTransactionError

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Native model ownership contracts require POSIX PHP')


class PhpTrust:
    def __init__(self, parent):
        self.parent = parent
        self.path = parent/'native-config.xml'
        self.state = parent/'state'; self.state.mkdir(mode=0o700)
        (parent/'fenced-native-trust-fixture').write_text('fixture-only')
        self.identity = {'uid': os.geteuid(), 'gid': os.getegid()}
        example = Path(__file__).resolve().parents[4]/'proto/examples/valid/relay-trust-settings-response.json'
        self.desired = json.loads(example.read_text())
        nodes = model_nodes(self.desired)
        root = ET.fromstring('<opnsense><system><hostname>retained-host</hostname></system><OPNsense>'
                             '<NetHubAgent><enabled>1</enabled><unrelated>retained-setting</unrelated></NetHubAgent>'
                             '<OtherPlugin><enabled>1</enabled></OtherPlugin></OPNsense></opnsense>')
        model = root.find('OPNsense/NetHubAgent')
        fields = {'console_url': 'https://console.example.com', 'device_id': self.desired['device_id'],
                  'device_secret': 't'*43, 'domain_claim': 'public-fixture-claim', 'frp_token': 'f'*64,
                  'server_addr': 'relay.example.com', 'server_name': 'relay.example.com', 'server_port': '7000',
                  'subdomain': 'abcdefgh', 'relay_ca': nodes['relay_ca'], 'relay_trust_state': ''}
        for key, value in fields.items():
            ET.SubElement(model, key).text = value
        ET.ElementTree(root).write(self.path, encoding='utf-8')
        self.path.chmod(0o600)

    def call(self, action, request, fault=''):
        value = {'config_file': str(self.path), 'state_directory': str(self.state), 'owner': os.geteuid(),
                 'config_identity': self.identity, 'action': action, 'request': request, 'fault': fault}
        php = os.environ.get('NETHUB_TEST_PHP') or shutil.which('php')
        assert php, 'Native PHP is required'
        result = subprocess.run([php, str(ROOT/'tests/relay_trust_store_contract.php'),
            str(ROOT/'src/usr/local/opnsense/scripts/nethub-agent/relay_trust_store.php')],
            input=json.dumps(value).encode(), capture_output=True, timeout=8)
        assert len(result.stdout) <= 65536
        reply = json.loads(result.stdout)
        if result.returncode or reply.get('success') is not True:
            assert self.desired['desired']['ca_pem'] not in result.stdout.decode()
            assert 't'*43 not in result.stdout.decode()
            raise ValueError('Native trust fixture refused the operation')
        return reply['result']

    def request(self):
        current = self.call('read', [])
        return {'binding': current['binding'], 'before': current['nodes'], 'after': model_nodes(self.desired)}

    def change(self, field, value):
        tree = ET.parse(self.path)
        tree.find('OPNsense/NetHubAgent/'+field).text = value
        tree.write(self.path, encoding='utf-8')


@pytest.fixture
def native(tmp_path):
    return PhpTrust(tmp_path)


def test_real_model_save_readback_idempotence_and_fenced_rollback(native):
    before = ET.parse(native.path)
    request = native.request()
    assert native.call('install', request) == {'selected': True, 'changed': True}
    assert native.call('read', [])['nodes'] == request['after']
    assert native.call('install', request) == {'selected': True, 'changed': False}
    after = ET.parse(native.path)
    for path in ('system', 'OPNsense/OtherPlugin', 'OPNsense/NetHubAgent/unrelated'):
        assert ET.tostring(before.find(path)) == ET.tostring(after.find(path))
    assert native.call('rollback', request) == {'selected': True, 'changed': True}
    assert native.call('rollback', request) == {'selected': True, 'changed': False}
    assert native.call('read', [])['nodes'] == request['before']


@pytest.mark.parametrize('field,value', [('device_secret', 'u'*43), ('device_id', '22222222-2222-4222-8222-222222222222'),
    ('server_name', 'other.example.com'), ('console_url', 'https://other.example.com'), ('domain_claim', 'different-claim')])
def test_stale_enrollment_cannot_install_or_rollback(native, field, value):
    request = native.request()
    native.change(field, value)
    before = native.path.read_bytes()
    for action in ('install', 'rollback'):
        with pytest.raises(ValueError): native.call(action, request)
        assert native.path.read_bytes() == before


@pytest.mark.parametrize('marker', ['disabled', 'stopped', 'revoked', 'uninstalling'])
def test_inactive_blocks_install_but_allows_exact_rollback(native, marker):
    request = native.request()
    native.call('install', request)
    (native.state/marker).write_text('operator fixture')
    before = native.path.read_bytes()
    with pytest.raises(ValueError): native.call('install', request)
    assert native.path.read_bytes() == before
    assert native.call('rollback', request)['selected'] is True
    assert (native.state/marker).exists()


def test_disabled_model_is_preserved_during_recovery(native):
    request = native.request(); native.call('install', request)
    native.change('enabled', '0')
    with pytest.raises(ValueError): native.call('install', request)
    assert native.call('rollback', request)['selected'] is True
    assert ET.parse(native.path).findtext('OPNsense/NetHubAgent/enabled') == '0'


def test_unknown_local_trust_change_cannot_be_overwritten(native):
    request = native.request()
    native.change('relay_ca', base64.b64encode(b'locally changed public material').decode())
    before = native.path.read_bytes()
    for action in ('install', 'rollback'):
        with pytest.raises(ValueError): native.call(action, request)
        assert native.path.read_bytes() == before


@pytest.mark.parametrize('fault', ['validation', 'drop'])
def test_validation_and_missing_durable_save_cannot_report_success(native, fault):
    request = native.request(); before = native.path.read_bytes()
    with pytest.raises(ValueError): native.call('install', request, fault=fault)
    assert native.path.read_bytes() == before


def test_lost_write_reply_is_recovered_by_exact_retry(native):
    request = native.request()
    with pytest.raises(ValueError): native.call('install', request, fault='lost_reply')
    assert native.call('read', [])['nodes'] == request['after']
    assert native.call('install', request) == {'selected': True, 'changed': False}


@pytest.mark.parametrize('field,value', [('generation', True), ('generation', 0), ('generation_id', 'invalid'),
    ('server_name', 'other.example.com'), ('bundle_fingerprint', '0'*64), ('valid_until', '2026-01-01T00:00:00.000000Z')])
def test_generation_metadata_is_validated_at_the_native_boundary(native, field, value):
    request = native.request(); bad = copy.deepcopy(native.desired); bad['desired'][field] = value
    request['after'] = model_nodes(bad)
    before = native.path.read_bytes()
    with pytest.raises(ValueError): native.call('install', request)
    assert native.path.read_bytes() == before


def test_equal_epoch_mutation_and_rollback_are_not_new_installations(native):
    first = native.request(); native.call('install', first)
    next_request = native.request()
    changed = copy.deepcopy(native.desired)
    changed['desired']['published_at'] = '2026-10-20T00:00:01.000000Z'
    next_request['after'] = model_nodes(changed)
    with pytest.raises(ValueError): native.call('install', next_request)
    changed['desired'].update(generation=2, generation_id='55555555-5555-4555-8555-555555555555')
    next_request['after'] = model_nodes(changed)
    assert native.call('install', next_request)['changed'] is True
    with pytest.raises(ValueError): native.call('install', first)
    assert native.call('rollback', next_request)['changed'] is True


@pytest.mark.parametrize('mode', [0o644, 0o666])
def test_native_configuration_permissions_are_not_relaxed(native, mode):
    request = native.request(); native.path.chmod(mode)
    before = native.path.read_bytes()
    with pytest.raises(ValueError): native.call('install', request)
    assert native.path.read_bytes() == before


def test_readable_native_core_mode_is_preserved(native):
    native.path.chmod(0o640)
    request = native.request(); native.call('install', request)
    assert native.path.stat().st_mode & 0o777 == 0o640


def test_native_file_hardlink_is_refused(native):
    request = native.request(); os.link(native.path, native.parent/'alias.xml')
    with pytest.raises(ValueError): native.call('install', request)


def test_real_python_backend_and_php_writer_round_trip(native):
    def run(arguments, input, **kwargs):
        value = json.loads(input)
        result = native.call(value['action'], value['request'])
        return subprocess.CompletedProcess(arguments, 0, json.dumps({'success': True, 'result': result}).encode(), b'')
    backend = NativeTrustBackend(run=run, configuration=native.path)
    current = backend.read()
    after = model_nodes(native.desired)
    assert backend.replace(current['binding'], current['nodes'], after) is True
    assert backend.replace(current['binding'], current['nodes'], after) is False
    assert backend.replace(current['binding'], current['nodes'], after, rollback=True) is True


@pytest.fixture
def native_transaction(native):
    config = native.parent/'plugin'; config.mkdir(mode=0o700)
    calls = []
    def run(arguments, input, **kwargs):
        value = json.loads(input)
        result = native.call(value['action'], value['request'])
        return subprocess.CompletedProcess(arguments, 0, json.dumps({'success': True, 'result': result}).encode(), b'')
    backend = NativeTrustBackend(run=run, configuration=native.path)
    def stop(): calls.append('stop'); return True
    def reload(): calls.append('reload'); return True
    transaction = TrustTransaction(config, backend, stop, reload,
        clock=lambda: datetime(2026, 10, 21, tzinfo=timezone.utc).timestamp(), openssl=shutil.which('openssl'))
    return native, transaction, calls


def test_real_php_and_durable_file_journal_apply_once(native_transaction):
    native, transaction, calls = native_transaction
    before = native.call('read', [])
    assert transaction.apply(native.desired)['success'] is True
    assert transaction.ca.read_text() == native.desired['desired']['ca_pem']
    assert native.call('read', [])['nodes'] == model_nodes(native.desired)
    assert transaction.apply(native.desired)['success'] is True
    assert calls == ['stop', 'reload']
    assert transaction.read()['phase'] == 'applied'
    assert transaction.ca.stat().st_mode & 0o777 == 0o600
    assert before['binding'] == native.call('read', [])['binding']


def test_real_php_success_followed_by_reload_failure_rolls_back(native_transaction):
    native, transaction, calls = native_transaction
    before = native.call('read', [])
    transaction.reload = lambda: False
    with pytest.raises(TrustTransactionError): transaction.apply(native.desired)
    assert native.call('read', []) == before
    assert not transaction.ca.exists()
    assert transaction.read()['phase'] == 'rolled_back'
    assert calls == ['stop', 'stop']


def test_actual_native_save_response_loss_is_recovered_by_journal(native_transaction):
    native, transaction, calls = native_transaction
    before = native.call('read', [])
    original = native.call
    def lose_once(action, request, fault=''):
        return original(action, request, fault='lost_reply' if action == 'install' else fault)
    native.call = lose_once
    with pytest.raises(TrustTransactionError): transaction.apply(native.desired)
    assert original('read', []) == before
    assert transaction.read()['phase'] == 'rolled_back'
    assert not transaction.ca.exists()


def test_native_model_and_ca_restore_after_process_death(native_transaction):
    native, transaction, calls = native_transaction
    before = native.call('read', [])
    class PowerLoss(BaseException): pass
    original = transaction._write
    def die_after_written(value):
        original(value)
        if value['phase'] == 'written': raise PowerLoss()
    transaction._write = die_after_written
    with pytest.raises(PowerLoss): transaction.apply(native.desired)
    assert native.call('read', [])['nodes'] == model_nodes(native.desired)
    assert transaction.ca.exists()
    transaction._write = original
    calls.clear()
    assert transaction.recover()['phase'] == 'rolled_back'
    assert native.call('read', []) == before
    assert not transaction.ca.exists() and calls == ['stop']
