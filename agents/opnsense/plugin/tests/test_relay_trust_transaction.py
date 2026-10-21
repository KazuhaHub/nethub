"""Inject crashes and ordinary failures at durable public trust boundaries."""
import base64
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src/usr/local/opnsense/scripts/nethub-agent'))
from certificate_key import KeyStore
from relay_trust_backend import model_nodes
from relay_trust_transaction import TrustTransaction, TrustTransactionError
from test_relay_trust import authority, bundle


NOW = datetime(2026, 10, 21, tzinfo=timezone.utc).timestamp()


def example(name='relay-trust-settings-response'):
    return json.loads((Path(__file__).resolve().parents[4]/'proto/examples/valid'/(name+'.json')).read_text())


class SimulatedPowerLoss(BaseException):
    pass


class Model:
    def __init__(self):
        value = example()
        self.current = {'binding': 'a'*64, 'device_id': value['device_id'], 'server_name': value['desired']['server_name'],
                        'nodes': dict(model_nodes(value), relay_trust_state='')}
        self.operations = []
        self.fault = None

    def read(self):
        return copy.deepcopy(self.current)

    def replace(self, binding, before, after, rollback=False):
        if binding != self.current['binding'] or self.current['nodes'] not in (before, after):
            raise ValueError('Changed enrollment or native model')
        self.operations.append('rollback' if rollback else 'install')
        if self.fault == 'before_write' and not rollback:
            raise ValueError('Model rejected candidate')
        self.current['nodes'] = copy.deepcopy(before if rollback else after)
        if self.fault == 'after_write' and not rollback:
            raise ValueError('Model save reply lost')
        if self.fault == 'power_loss' and not rollback:
            raise SimulatedPowerLoss()
        return True


@pytest.fixture
def transaction(tmp_path):
    tmp_path.chmod(0o700)
    model = Model()
    pem = example()['desired']['ca_pem'].encode()
    (tmp_path/'relay-ca.pem').write_bytes(pem)
    (tmp_path/'relay-ca.pem').chmod(0o600)
    calls = []
    def stop(): calls.append('stop'); return True
    def reload(): calls.append('reload'); return True
    value = TrustTransaction(tmp_path, model, stop, reload, clock=lambda: NOW, openssl=shutil.which('openssl'))
    value.calls = calls
    return value


def test_durable_application_and_lost_report_retry_do_not_reinstall(transaction):
    value = example()
    assert transaction.apply(value) == {'success': True, 'phase': 'applied', 'generation': 1, 'confirmed': False}
    assert transaction.apply(value)['success'] is True
    assert transaction.backend.operations == ['install']
    assert transaction.calls == ['reload']
    reply = example('relay-trust-applied-response')
    assert transaction.confirm(reply)['confirmed'] is True
    assert transaction.confirm(reply)['confirmed'] is True
    reply['agent_protocol_version'] = '1.6.0'
    assert transaction.confirm(reply)['confirmed'] is True
    assert transaction.read()['receipt']['agent_protocol_version'] == '1.5.0'
    assert transaction.calls == ['reload']
    assert transaction.path.read_bytes() == KeyStore._encoded(transaction.read())


def test_wrong_receipt_retains_good_local_application(transaction):
    transaction.apply(example())
    reply = example('relay-trust-applied-response'); reply['generation'] = 2
    with pytest.raises(TrustTransactionError, match='applied trust was retained'):
        transaction.confirm(reply)
    assert transaction.read()['phase'] == 'applied'
    assert transaction.backend.operations == ['install']
    assert transaction.read()['receipt'] is None


def test_server_acceptance_timestamp_cannot_change_after_retry(transaction):
    transaction.apply(example()); reply = example('relay-trust-applied-response')
    transaction.confirm(reply)
    reply['accepted_at'] = '2026-10-21T00:00:01.000000Z'
    with pytest.raises(TrustTransactionError): transaction.confirm(reply)
    assert transaction.read()['receipt']['accepted_at'] != reply['accepted_at']


def changed_material(transaction):
    # Initial file absence is a material change without generating a fixture key.
    transaction.ca.unlink()
    return example()


@pytest.mark.parametrize('fault', ['before_write', 'after_write'])
def test_failed_or_lost_model_write_rolls_back_exact_nodes(transaction, fault):
    original = transaction.backend.read()
    value = changed_material(transaction)
    transaction.backend.fault = fault
    with pytest.raises(TrustTransactionError): transaction.apply(value)
    assert transaction.backend.read() == original
    assert not transaction.ca.exists()
    assert transaction.read()['phase'] == 'rolled_back'
    assert transaction.calls == ['stop', 'stop']
    assert transaction.read()['attempts'] == 1


@pytest.mark.parametrize('boundary', ['prepared', 'model', 'ca', 'written', 'reload'])
def test_power_loss_at_each_mutation_boundary_recovers_without_network_or_restart(transaction, boundary):
    original = transaction.backend.read()
    value = changed_material(transaction)
    write, replace_ca, reload = transaction._write, transaction._replace_ca, transaction.reload
    def persist(record):
        write(record)
        if record['phase'] == boundary:
            raise SimulatedPowerLoss()
    def ca(record, rollback=False):
        replace_ca(record, rollback)
        if boundary == 'ca' and not rollback:
            raise SimulatedPowerLoss()
    def restart():
        reload()
        if boundary == 'reload': raise SimulatedPowerLoss()
        return True
    if boundary == 'model': transaction.backend.fault = 'power_loss'
    transaction._write, transaction._replace_ca, transaction.reload = persist, ca, restart
    with pytest.raises(SimulatedPowerLoss): transaction.apply(value)
    transaction._write, transaction._replace_ca, transaction.reload = write, replace_ca, reload
    transaction.backend.fault = None
    transaction.calls.clear()
    assert transaction.recover()['phase'] == 'rolled_back'
    assert transaction.backend.read() == original and not transaction.ca.exists()
    assert transaction.calls == ['stop']
    assert transaction.recover() is None


def test_failed_reload_rolls_back_and_keeps_tunnel_stopped(transaction):
    original = transaction.backend.read()
    value = changed_material(transaction)
    transaction.reload = lambda: False
    with pytest.raises(TrustTransactionError): transaction.apply(value)
    assert transaction.backend.read() == original and not transaction.ca.exists()
    assert transaction.read()['phase'] == 'rolled_back'


def test_pending_recovery_never_overwrites_unrelated_native_changes(transaction):
    value = changed_material(transaction)
    transaction.backend.fault = 'power_loss'
    with pytest.raises(SimulatedPowerLoss): transaction.apply(value)
    transaction.backend.current['binding'] = 'b'*64
    current = transaction.backend.read()
    with pytest.raises(TrustTransactionError, match='startup must remain blocked'): transaction.recover()
    assert transaction.backend.read() == current
    assert transaction.read()['phase'] == 'prepared'


def test_unknown_ca_bytes_block_recovery_and_are_retained(transaction):
    value = changed_material(transaction)
    transaction.backend.fault = 'power_loss'
    with pytest.raises(SimulatedPowerLoss): transaction.apply(value)
    transaction.ca.write_bytes(b'unrelated local material'); transaction.ca.chmod(0o600)
    model = transaction.backend.read()
    with pytest.raises(TrustTransactionError): transaction.recover()
    assert transaction.ca.read_bytes() == b'unrelated local material'
    assert transaction.backend.read() == model
    assert transaction.read()['phase'] == 'prepared'


def test_retry_budget_and_backoff_survive_new_instances(transaction):
    transaction.backend.fault = 'before_write'
    value = example()
    for attempt in range(1, 4):
        with pytest.raises(TrustTransactionError): transaction.apply(value)
        assert transaction.read()['attempts'] == attempt
        result = transaction.apply(value)
        assert result['phase'] == ('retry_wait' if attempt < 3 else 'retry_exhausted')
        transaction.clock = lambda attempt=attempt: NOW+301*attempt
    assert transaction.backend.operations.count('install') == 3
    assert transaction.apply(value)['phase'] == 'retry_exhausted'
    next_value = example(); next_value['desired'].update(generation=2, generation_id='55555555-5555-4555-8555-555555555555')
    transaction.backend.fault = None
    assert transaction.apply(next_value)['success'] is True
    assert transaction.read()['attempts'] == 1


def test_rolled_back_highest_desired_epoch_still_rejects_older_or_mutated_input(transaction):
    value = example(); value['desired'].update(generation=2, generation_id='55555555-5555-4555-8555-555555555555')
    transaction.backend.fault = 'before_write'
    with pytest.raises(TrustTransactionError): transaction.apply(value)
    with pytest.raises(TrustTransactionError): transaction.apply(example())
    value['desired']['published_at'] = '2026-10-20T00:00:01.000000Z'
    with pytest.raises(TrustTransactionError): transaction.apply(value)
    assert transaction.read()['snapshot']['desired']['generation'] == 2


def test_expired_old_snapshot_cannot_deadlock_new_valid_trust(transaction):
    transaction.apply(example())
    original = transaction.backend.read()
    transaction.clock = lambda: datetime(2037, 1, 1, tzinfo=timezone.utc).timestamp()
    # Historical recovery parsing remains possible; it does not assert live trust.
    assert transaction.read()['phase'] == 'applied'
    with pytest.raises(TrustTransactionError): transaction.apply(example())
    assert transaction.backend.read() == original


@pytest.mark.parametrize('path', ['transaction.json', 'relay-ca.pem'])
def test_symlink_or_hardlinked_managed_material_is_never_replaced(transaction, path):
    transaction.apply(example())
    source = transaction.path if path == 'transaction.json' else transaction.ca
    if os.name == 'nt': pytest.skip('Protected link contracts require POSIX')
    alias = source.with_name(source.name+'.alias'); os.link(source, alias)
    with pytest.raises(TrustTransactionError): transaction.apply(example())
    assert alias.read_bytes() == source.read_bytes()


def test_corrupt_and_unknown_journal_material_requires_review(transaction):
    transaction.apply(example())
    original = transaction.path.read_bytes()
    transaction.path.write_bytes(original.replace(b'"version":1', b'"version":1,"version":1'))
    with pytest.raises(TrustTransactionError): transaction.read()
    transaction.path.write_bytes(original)
    (transaction.directory/'unknown').write_text('retain')
    with pytest.raises(TrustTransactionError): transaction.read()
    assert (transaction.directory/'unknown').read_text() == 'retain'


def test_failed_actual_ca_change_restores_previous_applied_generation(transaction, authority):
    transaction.clock = lambda: datetime.now(timezone.utc).timestamp()
    transaction.apply(example())
    before = transaction.backend.read(); ca = transaction.ca.read_bytes()
    value = bundle(example(), [authority(1)])
    value['desired'].update(generation=2, generation_id='55555555-5555-4555-8555-555555555555',
                            published_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
    transaction.reload = lambda: False
    with pytest.raises(TrustTransactionError): transaction.apply(value)
    assert transaction.backend.read() == before
    assert transaction.ca.read_bytes() == ca
    record = transaction.read()
    assert record['phase'] == 'rolled_back' and record['snapshot']['desired']['generation'] == 2
    assert record['before']['relay_trust_state'] == before['nodes']['relay_trust_state']


def test_applied_local_change_prevents_automatic_receipt_and_reinstall(transaction):
    transaction.apply(example())
    transaction.backend.current['binding'] = 'b'*64
    with pytest.raises(TrustTransactionError): transaction.confirm(example('relay-trust-applied-response'))
    with pytest.raises(TrustTransactionError): transaction.apply(example())
    assert transaction.read()['receipt'] is None
    assert transaction.backend.operations == ['install']


def test_rolling_back_a_failed_model_only_epoch_does_not_stop_good_tunnel(transaction):
    transaction.apply(example()); transaction.calls.clear()
    value = example(); value['desired'].update(generation=2, generation_id='55555555-5555-4555-8555-555555555555')
    transaction.backend.fault = 'after_write'
    with pytest.raises(TrustTransactionError): transaction.apply(value)
    assert transaction.calls == []
    assert transaction.read()['phase'] == 'rolled_back'


@pytest.mark.skipif(os.name == 'nt', reason='Native symlink and ownership contracts require POSIX')
def test_symlink_and_unsafe_journal_permissions_are_refused(transaction):
    transaction.apply(example())
    saved = transaction.path.read_bytes()
    target = transaction.config/'saved-public-journal'; transaction.path.rename(target)
    transaction.path.symlink_to(target)
    with pytest.raises(TrustTransactionError): transaction.read()
    transaction.path.unlink(); target.rename(transaction.path)
    transaction.path.chmod(0o644)
    with pytest.raises(TrustTransactionError): transaction.read()
    assert transaction.path.read_bytes() == saved


def test_terminal_journal_cleanup_keeps_managed_ca_and_is_retryable(transaction):
    transaction.apply(example()); ca = transaction.ca.read_bytes()
    transaction.forget()
    assert not transaction.directory.exists() and transaction.ca.read_bytes() == ca
    transaction.forget()


def test_pending_or_unknown_artifacts_cannot_be_forgotten(transaction):
    transaction.backend.fault = 'power_loss'
    with pytest.raises(SimulatedPowerLoss): transaction.apply(example())
    original = transaction.path.read_bytes()
    with pytest.raises(TrustTransactionError): transaction.forget()
    assert transaction.path.read_bytes() == original
    transaction.backend.fault = None; transaction.recover()
    (transaction.directory/'retain').write_text('unknown')
    with pytest.raises(TrustTransactionError): transaction.forget()
    assert transaction.path.exists() and (transaction.directory/'retain').exists()
