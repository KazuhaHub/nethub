"""Bind desired configuration and watchdog recovery to verified managed CA bytes."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

import test_reconcile as fixture
from test_relay_trust import authority, bundle
from test_watchdog import MODULE as WATCHDOG
from relay_trust_backend import model_nodes


def example():
    return json.loads((fixture.ROOT.parents[2]/'proto/examples/valid/relay-trust-settings-response.json').read_text())


def install_fixture(case, value):
    """Simulate the separate model/file transaction only inside a temporary fixture."""
    path = case.root/'conf/config.xml'
    tree = ET.parse(path); model = tree.find('OPNsense/NetHubAgent')
    for name, text in dict(model_nodes(value), device_id=value['device_id'], server_name=value['desired']['server_name']).items():
        node = model.find(name)
        if node is None: node = ET.SubElement(model, name)
        node.text = text
    tree.write(path, encoding='utf-8')
    (case.agent.config/'relay-ca.pem').write_text(value['desired']['ca_pem'])
    (case.agent.config/'relay-ca.pem').chmod(0o600)


@pytest.fixture
def managed():
    case = fixture.ReconcileTests(); case.setUp()
    install_fixture(case, example())
    yield case
    case.doCleanups()


def test_managed_ca_binds_desired_hash_and_unchanged_trust_does_not_restart(managed):
    before = (managed.root/'conf/config.xml').read_bytes()
    first = managed.agent.apply('reconcile')
    assert first['success'] is True and first['action'] == 'restart'
    digest = hashlib.sha256(example()['desired']['ca_pem'].encode()).hexdigest()
    assert managed.agent.live.read_text() == '# nethub-relay-ca-sha256: '+digest+'\n'+managed.render
    assert managed.agent.apply('reconcile')['action'] == 'unchanged'
    assert managed.mutations() == ['onerestart']
    assert (managed.root/'conf/config.xml').read_bytes() == before


def test_ca_change_reloads_even_when_template_text_is_identical(managed, authority):
    assert managed.agent.apply('reconcile')['success'] is True
    first = managed.agent.live.read_bytes()
    value = bundle(example(), [authority(1)])
    value['desired'].update(generation=2, generation_id='55555555-5555-4555-8555-555555555555',
                            published_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
    install_fixture(managed, value)
    assert managed.agent.apply('reconcile')['action'] == 'restart'
    assert managed.agent.live.read_bytes() != first
    assert managed.agent.apply('reconcile')['action'] == 'unchanged'
    assert managed.mutations() == ['onerestart', 'onerestart']


def test_new_epoch_with_identical_ca_does_not_restart_a_good_tunnel(managed):
    assert managed.agent.apply('reconcile')['success'] is True
    value = example(); value['desired'].update(generation=2, generation_id='55555555-5555-4555-8555-555555555555')
    install_fixture(managed, value)
    assert managed.agent.apply('reconcile')['action'] == 'unchanged'
    assert managed.mutations() == ['onerestart']


@pytest.mark.parametrize('bad', ['expired', 'bad_digest', 'bad_encoding', 'missing_ca', 'wrong_window'])
def test_invalid_managed_trust_stops_tunnel_and_watchdog_cannot_revive_it(managed, bad):
    value = example()
    if bad == 'expired':
        value['desired'].update(not_before='1999-01-01T00:00:00.000000Z', published_at='1999-01-02T00:00:00.000000Z',
                                valid_until='2000-01-01T00:00:00.000000Z')
    elif bad == 'bad_digest': value['desired']['bundle_fingerprint'] = '0'*64
    elif bad == 'wrong_window': value['desired']['valid_until'] = '2035-01-01T00:00:00.000000Z'
    install_fixture(managed, value)
    if bad in ('bad_encoding', 'missing_ca'):
        path = managed.root/'conf/config.xml'; tree = ET.parse(path)
        tree.find('OPNsense/NetHubAgent/'+('relay_ca' if bad == 'missing_ca' else 'relay_trust_state')).text = '' if bad == 'missing_ca' else 'invalid!'
        tree.write(path, encoding='utf-8')
    result = managed.agent.apply('reconcile')
    assert result['success'] is False and not managed.active
    watchdog = WATCHDOG.Watchdog(managed.root, managed.command)
    assert watchdog.apply()['action'] == 'disabled'
    assert managed.mutations() == ['onestop']
    assert not (managed.agent.state/'revoked').exists()


def test_watchdog_rejects_old_backup_bound_to_another_ca(managed, authority):
    assert managed.agent.apply('reconcile')['success'] is True
    value = bundle(example(), [authority(1)])
    value['desired'].update(generation=2, generation_id='55555555-5555-4555-8555-555555555555',
                            published_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
    install_fixture(managed, value)
    assert managed.agent.apply('reconcile')['success'] is True
    managed.active = False; managed.calls.clear()
    watchdog = WATCHDOG.Watchdog(managed.root, managed.command)
    assert watchdog.apply()['action'] == 'last_good_trust_mismatch'
    assert managed.mutations() == []
    assert json.loads(watchdog.journal.read_text())['abandoned'] is True
    assert managed.agent.apply('reconcile')['action'] == 'quarantined'


def test_watchdog_rejects_unbound_backup_after_first_managed_generation(managed):
    assert managed.agent.apply('reconcile')['success'] is True
    managed.active = False; managed.calls.clear()
    watchdog = WATCHDOG.Watchdog(managed.root, managed.command)
    assert watchdog.apply()['action'] == 'last_good_trust_mismatch'
    assert managed.mutations() == []


def test_restored_enabled_intent_waits_for_reconcile_without_quarantining(managed):
    assert managed.agent.apply('reconcile')['success'] is True
    path = managed.root/'conf/config.xml'
    tree = ET.parse(path)
    tree.find('OPNsense/NetHubAgent/enabled').text = '0'
    tree.write(path, encoding='utf-8')
    assert managed.agent.apply('reconcile')['action'] == 'stop'
    assert not managed.active
    tree.find('OPNsense/NetHubAgent/enabled').text = '1'
    tree.write(path, encoding='utf-8')
    managed.calls.clear()
    watchdog = WATCHDOG.Watchdog(managed.root, managed.command)
    assert watchdog.apply()['action'] == 'awaiting_reconcile'
    assert not watchdog.journal.exists()
    assert managed.mutations() == []
    assert managed.agent.apply('reconcile')['action'] == 'start'
    assert managed.active
    assert watchdog.apply()['action'] == 'running'


def test_watchdog_can_recover_a_backup_under_the_same_managed_ca(managed):
    assert managed.agent.apply('reconcile')['success'] is True
    managed.agent.backup.write_bytes(managed.agent.live.read_bytes())
    managed.agent.backup.chmod(0o600)
    managed.active = False; managed.calls.clear()
    watchdog = WATCHDOG.Watchdog(managed.root, managed.command)
    assert watchdog.apply()['action'] == 'rollback'
    assert managed.mutations() == ['onestart']


def test_watchdog_does_not_revive_an_expired_running_managed_tunnel(managed):
    value = example(); value['desired']['valid_until'] = '2000-01-01T00:00:00.000000Z'
    install_fixture(managed, value)
    watchdog = WATCHDOG.Watchdog(managed.root, managed.command)
    assert watchdog.apply()['action'] == 'disabled'
    assert managed.mutations() == ['onestop']
