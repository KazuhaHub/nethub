"""Fault-test the local journal with a fenced model, without a native GUI change."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/nethub-agent'))
from certificate_key import KeyStore
from certificate_transaction import CertificateTransaction, CertificateTransactionError


class Interrupted(BaseException):
    """Model process death, which ordinary exception recovery cannot intercept."""


class NativeModel:
    """A test backend that never invokes OPNsense or reads the host config."""

    def __init__(self, directory):
        self.directory = directory
        self.native = {'ref': 'original', 'owned': None, 'unrelated': 'retain this value'}
        self.events = []
        self.healthy = True
        self.crash_after_install = False
        self.operator_change = False

    def snapshot(self, value):
        return json.loads((self.directory / ('snapshot-' + value['nonce'] + '.json')).read_bytes())

    def prepare(self, nonce, digest, good):
        self.events.append('prepare')
        if good is not None:
            assert self.native['ref'] == good['refid']
            assert hashlib.sha256(KeyStore._encoded(self.native['owned'])).hexdigest() == good['native_hash']
        value = {'before': {key: self.native[key] for key in ('ref', 'owned')},
                 'after': {'ref': 'a' * 13, 'owned': {'public_candidate_sha256': digest}}}
        raw = KeyStore._encoded(value)
        path = self.directory / ('snapshot-' + nonce + '.json')
        with path.open('xb') as stream:
            path.chmod(0o600)
            stream.write(raw)
        return {'refid': value['after']['ref'], 'port': 443,
                'native_hash': hashlib.sha256(KeyStore._encoded(value['after']['owned'])).hexdigest(),
                'snapshot_sha256': hashlib.sha256(raw).hexdigest()}

    def install(self, value):
        self.events.append('install')
        persisted = json.loads((self.directory / 'transaction.json').read_bytes())
        assert persisted['phase'] == 'prepared' and persisted['nonce'] == value['nonce']
        snapshot = self.snapshot(value)
        assert all(self.native[key] == field for key, field in snapshot['before'].items())
        self.native.update(snapshot['after'])
        if self.crash_after_install:
            raise Interrupted()
        return True

    def check(self, value):
        self.events.append('check')
        return all(self.native[key] == field for key, field in self.snapshot(value)['after'].items())

    def probe(self, value):
        self.events.append('probe')
        if self.operator_change:
            self.native['ref'] = 'operator-selected'
            self.native['unrelated'] = 'operator-updated'
        return self.healthy and not self.operator_change

    def rollback(self, value):
        self.events.append('rollback')
        snapshot = self.snapshot(value)
        current = {key: self.native[key] for key in ('ref', 'owned')}
        if current == snapshot['after']:
            self.native.update(snapshot['before'])
        elif current != snapshot['before']:
            raise RuntimeError('Private native conflict diagnostic')
        return True


@pytest.fixture
def transaction(tmp_path):
    tmp_path.chmod(0o700)
    directory = tmp_path / 'gui-apply'
    model = NativeModel(directory)
    clock = [1800000000]
    journal = CertificateTransaction(directory, model, clock=lambda: clock[0])
    value = {'agent_protocol_version': '1.3.0', 'device_id': '12345678-1234-1234-1234-123456789abc',
             'issued': {'generation': 1, 'generation_id': '23456789-2345-2345-2345-23456789abcd'}}
    (tmp_path / 'gui-certificate.json').write_bytes(KeyStore._encoded(value))
    (tmp_path / 'gui-certificate.json').chmod(0o600)
    return journal, model, value, clock


def stage(journal, value):
    (journal.directory.parent / 'gui-certificate.json').write_bytes(KeyStore._encoded(value))


def test_prepare_is_durable_before_install_and_unchanged_delivery_does_not_reinstall(transaction):
    journal, model, value, _ = transaction
    assert journal.apply(value)['phase'] == 'applied'
    assert model.events == ['prepare', 'install', 'probe', 'check']
    before = journal.path.read_bytes()
    assert journal.apply(value)['phase'] == 'applied'
    assert model.events[-2:] == ['check', 'probe'] and model.events.count('install') == 1
    assert journal.path.read_bytes() == before and model.native['unrelated'] == 'retain this value'
    if os.name != 'nt':
        assert journal.directory.stat().st_mode & 0o777 == 0o700
        assert journal.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('point', ['after_install', 'written'])
def test_new_process_recovers_interrupted_apply_without_network_or_new_key(transaction, point):
    journal, model, value, clock = transaction
    if point == 'after_install':
        model.crash_after_install = True
        with pytest.raises(Interrupted):
            journal.apply(value)
    else:
        write = journal._write

        def interrupt(record):
            write(record)
            if record['phase'] == 'written':
                raise Interrupted()

        with mock.patch.object(journal, '_write', side_effect=interrupt), pytest.raises(Interrupted):
            journal.apply(value)
    assert json.loads(journal.path.read_bytes())['phase'] in ('prepared', 'written')
    restarted = CertificateTransaction(journal.directory, model, clock=lambda: clock[0])
    assert restarted.recover()['phase'] == 'rolled_back'
    assert model.native == {'ref': 'original', 'owned': None, 'unrelated': 'retain this value'}
    before = journal.path.read_bytes()
    assert restarted.recover() is None and journal.path.read_bytes() == before
    assert not (journal.directory.parent / 'gui-key').exists()


def test_probe_failure_rolls_back_and_persists_retry_budget_across_instances(transaction):
    journal, model, value, clock = transaction
    model.healthy = False
    for attempt in range(1, 4):
        restarted = CertificateTransaction(journal.directory, model, clock=lambda: clock[0])
        with pytest.raises(CertificateTransactionError):
            restarted.apply(value)
        record = json.loads(journal.path.read_bytes())
        assert record['phase'] == 'rolled_back' and record['attempts'] == attempt
        assert model.native['ref'] == 'original' and model.native['owned'] is None
        if attempt < 3:
            assert restarted.apply(value)['phase'] == 'retry_wait'
        clock[0] += 301
    assert journal.apply(value)['phase'] == 'retry_exhausted'
    assert model.events.count('install') == 3
    newer = copy.deepcopy(value)
    newer['issued'] = {'generation': 2, 'generation_id': '3456789a-3456-3456-3456-3456789abcde'}
    stage(journal, newer)
    model.healthy = True
    assert journal.apply(newer)['phase'] == 'applied'
    assert json.loads(journal.path.read_bytes())['attempts'] == 1


def test_protocol_metadata_change_cannot_reinstall_or_reset_a_generation_budget(transaction):
    journal, model, value, _ = transaction
    assert journal.apply(value)['phase'] == 'applied'
    changed = dict(value, agent_protocol_version='1.4.0')
    stage(journal, changed)
    assert journal.apply(changed)['phase'] == 'applied'
    assert model.events.count('install') == 1


def test_protocol_metadata_change_keeps_a_failed_generation_retry_budget(transaction):
    journal, model, value, clock = transaction
    model.healthy = False
    with pytest.raises(CertificateTransactionError):
        journal.apply(value)
    changed = dict(value, agent_protocol_version='1.4.0')
    stage(journal, changed)
    assert journal.apply(changed)['phase'] == 'retry_wait'
    clock[0] += 301
    with pytest.raises(CertificateTransactionError):
        journal.apply(changed)
    assert json.loads(journal.path.read_bytes())['attempts'] == 2


def test_operator_change_is_not_overwritten_by_rollback(transaction):
    journal, model, value, _ = transaction
    model.operator_change = True
    with pytest.raises(CertificateTransactionError, match='local recovery'):
        journal.apply(value)
    assert model.native['ref'] == 'operator-selected' and model.native['unrelated'] == 'operator-updated'
    assert json.loads(journal.path.read_bytes())['phase'] == 'written'


@pytest.mark.parametrize('fault', ['snapshot', 'journal', 'candidate'])
def test_corrupt_or_changed_storage_never_reaches_a_native_write(transaction, fault):
    journal, model, value, _ = transaction
    if fault == 'candidate':
        stage(journal, {'changed': True})
        with pytest.raises(CertificateTransactionError):
            journal.apply(value)
        assert model.events == []
        return
    model.crash_after_install = True
    with pytest.raises(Interrupted):
        journal.apply(value)
    record = json.loads(journal.path.read_bytes())
    if fault == 'snapshot':
        (journal.directory / ('snapshot-' + record['nonce'] + '.json')).write_bytes(b'Changed private native snapshot')
    else:
        journal.path.write_bytes(b'{"version":1,"phase":"written"}\n')
    before = copy.deepcopy(model.native)
    with pytest.raises(CertificateTransactionError):
        journal.recover()
    assert model.native == before and 'rollback' not in model.events


def test_failed_journal_replacement_cannot_change_native_config(transaction):
    journal, model, value, _ = transaction
    before = copy.deepcopy(model.native)
    with mock.patch('certificate_transaction.os.replace', side_effect=OSError('Private filesystem diagnostic')):
        with pytest.raises(CertificateTransactionError) as caught:
            journal.apply(value)
    assert 'Private' not in str(caught.value)
    assert model.native == before and model.events == ['prepare']
    assert not list(journal.directory.glob('.transaction-*'))


def test_successful_renewal_records_the_previous_applied_native_identity(transaction):
    journal, model, value, _ = transaction
    journal.apply(value)
    previous = json.loads(journal.path.read_bytes())
    newer = copy.deepcopy(value)
    newer['issued'] = {'generation': 2, 'generation_id': '3456789a-3456-3456-3456-3456789abcde'}
    stage(journal, newer)
    assert journal.apply(newer)['phase'] == 'applied'
    current = json.loads(journal.path.read_bytes())
    assert current['last_good'] == {key: previous[key] for key in CertificateTransaction.GOOD}
    assert current['nonce'] != previous['nonce'] and model.native['unrelated'] == 'retain this value'
    assert not (journal.directory / ('snapshot-' + previous['nonce'] + '.json')).exists()
    assert len(list(journal.directory.glob('snapshot-*.json'))) == 1


def test_unknown_snapshot_accumulation_is_bounded_without_deleting_it(transaction):
    journal, model, value, _ = transaction
    journal.directory.mkdir(mode=0o700)
    for index in range(8):
        path = journal.directory / ('snapshot-' + format(index, '032x') + '.json')
        path.write_bytes(b'Unreferenced private material retained for local review')
        path.chmod(0o600)
    with pytest.raises(CertificateTransactionError):
        journal.apply(value)
    assert model.events == [] and len(list(journal.directory.glob('snapshot-*.json'))) == 8


@pytest.mark.skipif(os.name == 'nt', reason='POSIX snapshot ownership and mode enforcement runs on the appliance')
def test_unprotected_private_snapshot_cannot_drive_recovery(transaction):
    journal, model, value, _ = transaction
    model.crash_after_install = True
    with pytest.raises(Interrupted):
        journal.apply(value)
    record = json.loads(journal.path.read_bytes())
    (journal.directory / ('snapshot-' + record['nonce'] + '.json')).chmod(0o666)
    before = copy.deepcopy(model.native)
    with pytest.raises(CertificateTransactionError):
        journal.recover()
    assert model.native == before and 'rollback' not in model.events


def test_candidate_symlink_is_not_followed(transaction):
    journal, model, value, _ = transaction
    candidate = journal.directory.parent / 'gui-certificate.json'
    target = candidate.with_name('unrelated.json')
    candidate.rename(target)
    try:
        candidate.symlink_to(target)
    except OSError:
        if os.name == 'nt':
            pytest.skip('Windows symlink privilege is unavailable; mandatory on POSIX')
        raise
    with pytest.raises(CertificateTransactionError):
        journal.apply(value)
    assert target.read_bytes() == KeyStore._encoded(value) and model.events == []
