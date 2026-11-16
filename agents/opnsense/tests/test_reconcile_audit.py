"""Durable failure delivery retains original events and makes capacity loss explicit."""
import copy
import json
import os
from pathlib import Path
import sys
from unittest import mock

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'plugin/src/usr/local/opnsense/scripts/nethub-agent'
sys.path.insert(0, str(SCRIPTS))
import reconcile_audit as audit

DEVICE = '11111111-1111-4111-8111-111111111111'
OTHER = '22222222-2222-4222-8222-222222222222'


@pytest.fixture
def outbox(tmp_path):
    tmp_path.chmod(0o700)
    return audit.Outbox(tmp_path, DEVICE)


def state(outbox):
    return json.loads((outbox.directory / audit.FILE).read_text())


def write(outbox, value):
    p = outbox.directory / audit.FILE
    p.write_text(json.dumps(value))
    p.chmod(0o600)


def test_restart_and_lost_reply_keep_identical_original_events(outbox):
    outbox.record_failure()
    original = outbox.batch()
    assert len(original) == 1 and original[0]['kind'] == 'reconcile_failed'
    assert original == audit.Outbox(outbox.directory, DEVICE).batch() == outbox.batch()
    assert original[0]['count'] == 1 and original[0]['first_at'] == original[0]['last_at']
    assert (outbox.directory / audit.FILE).stat().st_mode & 0o777 == 0o600
    outbox.record_failure()
    assert outbox.batch()[0] == original[0]
    outbox.acknowledge([original[0]['event_id']])
    assert len(outbox.batch()) == 1 and outbox.batch()[0]['event_id'] != original[0]['event_id']


def test_capacity_never_evicts_originals_and_exports_explicit_aggregated_loss(outbox):
    for _ in range(audit.MAX_EVENTS):
        outbox.record_failure()
    originals = copy.deepcopy(state(outbox)['events'])
    for _ in range(11):
        outbox.record_failure()
    value = state(outbox)
    assert value['events'] == originals and value['overflow']['count'] == 11
    assert (outbox.directory / audit.FILE).stat().st_size < audit.MAX_BYTES
    received = []
    while batch := outbox.batch():
        assert len(batch) <= audit.MAX_BATCH
        received.extend(batch)
        outbox.acknowledge([e['event_id'] for e in batch])
    assert received[:audit.MAX_EVENTS] == originals
    assert len(received) == audit.MAX_EVENTS + 1
    assert received[-1]['kind'] == 'reconcile_failure_overflow' and received[-1]['count'] == 11
    assert sum(e['count'] for e in received) == audit.MAX_EVENTS + 11
    assert state(outbox)['events'] == [] and state(outbox)['overflow'] is None


def test_mutating_returned_batch_cannot_change_disk(outbox):
    outbox.record_failure()
    expected = state(outbox)
    outbox.batch()[0]['count'] = 9
    assert state(outbox) == expected


@pytest.mark.parametrize('ack', [[], [OTHER], [OTHER, OTHER], [OTHER] * 9, None, 'secret', [False]])
def test_unconfirmed_or_foreign_acknowledgement_cannot_discard_events(outbox, ack):
    outbox.record_failure()
    before = (outbox.directory / audit.FILE).read_bytes()
    with pytest.raises(audit.AuditOutboxError):
        outbox.acknowledge(ack)
    assert (outbox.directory / audit.FILE).read_bytes() == before


def test_acknowledgement_cannot_skip_prefix_or_replay_deletion(outbox):
    outbox.record_failure()
    outbox.record_failure()
    batch = outbox.batch()
    with pytest.raises(audit.AuditOutboxError):
        outbox.acknowledge([batch[1]['event_id']])
    outbox.acknowledge([batch[0]['event_id']])
    with pytest.raises(audit.AuditOutboxError):
        outbox.acknowledge([batch[0]['event_id']])
    assert outbox.batch() == batch[1:]


def test_changed_device_does_not_adopt_previous_enrollment_events(outbox):
    outbox.record_failure()
    before = (outbox.directory / audit.FILE).read_bytes()
    with pytest.raises(audit.AuditOutboxError):
        audit.Outbox(outbox.directory, OTHER).record_failure()
    assert (outbox.directory / audit.FILE).read_bytes() == before


@pytest.mark.parametrize('change', [
    lambda v: v.update(version=True),
    lambda v: v.update(private_diagnostic='do not publish'),
    lambda v: v.update(events=v['events'] * 2),
    lambda v: v['events'][0].update(kind='raw stderr'),
    lambda v: v['events'][0].update(count=True),
    lambda v: v['events'][0].update(count=2),
    lambda v: v['events'][0].update(first_at='2026-02-30T00:00:00.000000Z'),
    lambda v: v['events'][0].update(last_at='9999-12-31T00:00:00.000000Z'),
    lambda v: v['events'][0].update(event_id='00000000-0000-0000-0000-000000000000'),
    lambda v: v.update(overflow={'count': 0, 'first_at': v['events'][0]['first_at'], 'last_at': v['events'][0]['last_at']}),
])
def test_malformed_retained_state_is_refused_without_repair(outbox, change):
    outbox.record_failure()
    value = state(outbox)
    change(value)
    write(outbox, value)
    before = (outbox.directory / audit.FILE).read_bytes()
    with pytest.raises(audit.AuditOutboxError):
        outbox.record_failure()
    assert (outbox.directory / audit.FILE).read_bytes() == before


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'public', 'fifo', 'oversized', 'duplicate'])
def test_unsafe_storage_is_refused_without_touching_other_files(outbox, kind):
    target = outbox.directory / audit.FILE
    outside = outbox.directory / 'outside'
    outside.write_bytes(b'original protected bytes')
    outside.chmod(0o600)
    if kind == 'symlink':
        target.symlink_to(outside)
    elif kind == 'hardlink':
        os.link(outside, target)
    elif kind == 'fifo':
        os.mkfifo(target, 0o600)
    elif kind == 'duplicate':
        target.write_text('{"version":1,"version":1}')
        target.chmod(0o600)
    elif kind == 'oversized':
        target.write_bytes(b'x' * (audit.MAX_BYTES + 1))
        target.chmod(0o600)
    else:
        outbox.record_failure()
        target.chmod(0o644)
    with pytest.raises(audit.AuditOutboxError):
        outbox.batch()
    assert outside.read_bytes() == b'original protected bytes'


def test_unsafe_parent_and_directory_alias_are_refused(outbox):
    outbox.directory.chmod(0o755)
    with pytest.raises(audit.AuditOutboxError):
        outbox.record_failure()
    outbox.directory.chmod(0o700)
    alias = outbox.directory / 'alias'
    alias.symlink_to(outbox.directory, target_is_directory=True)
    with pytest.raises(audit.AuditOutboxError):
        audit.Outbox(alias, DEVICE).record_failure()


def test_failed_publication_retains_previous_bytes_and_removes_only_own_temporary(outbox):
    outbox.record_failure()
    path = outbox.directory / audit.FILE
    before = path.read_bytes()
    with mock.patch.object(audit.os, 'replace', side_effect=OSError('private path and secret')):
        with pytest.raises(audit.AuditOutboxError) as error:
            outbox.record_failure()
    assert 'secret' not in str(error.value) and 'path' not in str(error.value)
    assert path.read_bytes() == before
    assert not list(outbox.directory.glob('.reconcile-audit-*'))


def test_saturated_counter_refuses_without_wrapping_or_clearing(outbox):
    for _ in range(audit.MAX_EVENTS + 1):
        outbox.record_failure()
    value = state(outbox)
    value['overflow']['count'] = audit.MAX_COUNT
    write(outbox, value)
    before = (outbox.directory / audit.FILE).read_bytes()
    with pytest.raises(audit.AuditOutboxError, match='capacity exhausted'):
        outbox.record_failure()
    assert (outbox.directory / audit.FILE).read_bytes() == before


def test_directory_sync_failure_keeps_committed_original_for_read_only_recovery(outbox):
    outbox.record_failure()
    old = outbox.batch()
    real_sync = audit.os.fsync
    def sync(descriptor):
        import stat
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError('private filesystem diagnostic')
        real_sync(descriptor)
    with mock.patch.object(audit.os, 'fsync', side_effect=sync):
        with pytest.raises(audit.AuditOutboxError):
            outbox.record_failure()
    # Publication already happened: inspect the same file, never replay the
    # event append merely because its durability observation was unavailable.
    recovered = audit.Outbox(outbox.directory, DEVICE).batch()
    assert recovered[0] == old[0] and len(recovered) == 2


def test_deeply_nested_corruption_keeps_fixed_diagnostic_and_original_bytes(outbox):
    path = outbox.directory / audit.FILE
    raw = b'[' * 2000 + b'0' + b']' * 2000
    path.write_bytes(raw)
    path.chmod(0o600)
    with pytest.raises(audit.AuditOutboxError, match='^Invalid reconcile audit state$'):
        outbox.batch()
    assert path.read_bytes() == raw
