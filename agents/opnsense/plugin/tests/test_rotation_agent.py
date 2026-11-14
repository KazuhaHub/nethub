"""Dispatch rotation under the shared lock without exposing private assignments."""
from unittest import mock
import os
import signal
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

import pytest
import test_reconcile as base
from test_lifecycle_agent import case as enrolled_case


@pytest.mark.skipif(not sys.platform.startswith('freebsd'), reason='This case requires actual FreeBSD lockf')
def test_external_lock_mode_is_hardened_without_replacing_its_inode(case):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    case.agent.state.chmod(0o700)
    path = case.agent.state / 'reconcile.lock'
    subprocess.run(['/bin/sh', '-c', 'umask 022; exec /usr/bin/lockf -sk -t 0 "$1" /usr/bin/true',
                    'nethub-lock-mode', str(path)], check=True, capture_output=True, timeout=5)
    original = path.stat()
    assert original.st_mode & 0o777 == 0o644
    assert case.agent.apply('stop')['success'] is True
    actual = path.stat()
    assert actual.st_mode & 0o777 == 0o600
    assert (actual.st_dev, actual.st_ino) == (original.st_dev, original.st_ino)


def test_mutation_lock_never_follows_a_link(case):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    target = case.root / 'unrelated-lock'
    target.write_bytes(b'private value must remain unchanged')
    (case.agent.state / 'reconcile.lock').symlink_to(target)
    with pytest.raises(OSError):
        case.agent.open_mutation_lock()
    assert target.read_bytes() == b'private value must remain unchanged'
    assert case.active is True


def test_mutation_lock_does_not_chmod_a_shared_inode(case):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    target = case.root / 'unrelated-lock'
    target.write_bytes(b'')
    target.chmod(0o644)
    os.link(target, case.agent.state / 'reconcile.lock')
    assert case.agent.apply('stop')['success'] is False
    assert target.stat().st_mode & 0o777 == 0o644
    assert case.active is True


def test_mutation_lock_does_not_clear_unrecognized_content(case):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    path = case.agent.state / 'reconcile.lock'
    path.write_bytes(b'private value must remain unchanged')
    assert case.agent.apply('stop')['success'] is False
    assert path.read_bytes() == b'private value must remain unchanged'
    assert case.active is True


@pytest.fixture
def case():
    value = base.ReconcileTests()
    value.setUp()
    try:
        yield value
    finally:
        value.doCleanups()


def test_rotation_dispatch_uses_private_journal_and_existing_reconcile(case):
    expected = {'success': True, 'action': 'rotate', 'phase': 'applied', 'message': 'Credentials rotated'}
    backend = object()
    with mock.patch.object(case.agent, 'rotation_backend', return_value=backend), \
            mock.patch('rotation_transaction.rotate', return_value=expected) as operation:
        assert case.agent.apply('rotate') == expected
    journal, actual_backend, reconcile = operation.call_args.args
    assert journal.path == case.agent.state / 'rotation.json'
    assert actual_backend is backend and reconcile == case.agent.reconcile_locked
    assert not (case.agent.state / 'rotation.json').exists()


def test_rotation_contention_returns_busy_before_any_native_or_network_work(case):
    import fcntl
    case.agent.state.mkdir(parents=True, exist_ok=True)
    case.agent.state.chmod(0o700)
    path = case.agent.state / 'reconcile.lock'
    path.touch(mode=0o600)
    with path.open('r+b') as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (mock.patch.object(case.agent, 'rotate_locked') as rotate,
              mock.patch.object(base.MODULE.time, 'monotonic', side_effect=[100.0, 103.1])):
            result = case.agent.apply('rotate')
        assert result == {'success': False, 'message': 'Another service operation is running', 'action': 'busy'}
        rotate.assert_not_called()
    assert not (case.agent.state / 'rotation.json').exists()


def test_rotation_waits_for_short_contention_without_replaying_native_work(case):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    case.agent.state.chmod(0o700)
    path = case.agent.state / 'reconcile.lock'
    path.touch(mode=0o600)
    contested = threading.Event()
    flock = base.MODULE.fcntl.flock

    def observe_contention(*args):
        try:
            return flock(*args)
        except BlockingIOError:
            contested.set()
            raise

    expected = {'success': True, 'action': 'rotate', 'phase': 'applied'}

    def rotate_once():
        assert not (case.agent.state / 'rotation.json').exists()
        with path.open('r+b') as other:
            with pytest.raises(BlockingIOError):
                flock(other, base.MODULE.fcntl.LOCK_EX | base.MODULE.fcntl.LOCK_NB)
        return expected

    with path.open('r+b') as held:
        flock(held, base.MODULE.fcntl.LOCK_EX | base.MODULE.fcntl.LOCK_NB)

        def release():
            if contested.wait(5):
                flock(held, base.MODULE.fcntl.LOCK_UN)

        worker = threading.Thread(target=release)
        worker.start()
        try:
            with (mock.patch.object(base.MODULE.fcntl, 'flock', side_effect=observe_contention),
                  mock.patch.object(case.agent, 'rotate_locked', side_effect=rotate_once) as operation):
                assert case.agent.apply('rotate') == expected
            assert contested.is_set()
            operation.assert_called_once_with()
        finally:
            contested.set()
            worker.join(6)
    assert not worker.is_alive()


@pytest.mark.skipif(not sys.platform.startswith('freebsd'), reason='This case requires actual FreeBSD lockf')
def test_rotation_observes_actual_scheduler_lock_without_losing_busy_response(case):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    case.agent.state.chmod(0o700)
    path = case.agent.state / 'reconcile.lock'
    path.touch(mode=0o600)
    ready = case.root / 'rotation-lock-ready'
    holder = subprocess.Popen(['/usr/bin/lockf', '-sk', '-t', '0', str(path), sys.executable,
        '-c', 'from pathlib import Path; import sys,time; Path(sys.argv[1]).touch(); time.sleep(20)',
        str(ready)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        while not ready.exists():
            assert holder.poll() is None and time.monotonic() < deadline
            time.sleep(.02)
        started = time.monotonic()
        with mock.patch.object(case.agent, 'rotate_locked') as rotate:
            result = case.agent.apply('rotate')
        assert 2.8 <= time.monotonic() - started < 8
        assert result['success'] is False and result['action'] == 'busy'
        rotate.assert_not_called()
        assert not (case.agent.state / 'rotation.json').exists()
    finally:
        if holder.poll() is None:
            os.killpg(holder.pid, signal.SIGTERM)
        holder.wait(timeout=5)
    with mock.patch.object(case.agent, 'rotate_locked', return_value={'success': True}) as rotate:
        assert case.agent.apply('rotate') == {'success': True}
    rotate.assert_called_once_with()


@pytest.mark.parametrize('marker', ['revoked', 'uninstalling'])
def test_rotation_never_contacts_backend_after_local_removal_or_revocation(case, marker):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    (case.agent.state / marker).touch()
    with mock.patch.object(case.agent, 'rotation_backend') as backend, \
            mock.patch('relay_trust_sync.TrustSynchronizer.sync') as sync:
        result = case.agent.apply('rotate')
    assert result['success'] is False and result['action'] == 'rotate'
    backend.assert_not_called()
    sync.assert_not_called()


@pytest.mark.parametrize('marker', ['disabled', 'stopped'])
def test_explicit_rotation_refreshes_trust_without_releasing_stop_policy(enrolled_case, marker):
    agent = enrolled_case.agent
    configuration = enrolled_case.root / 'conf/config.xml'
    tree = ET.parse(configuration)
    tree.find('OPNsense/NetHubAgent/enabled').text = '0'
    tree.write(configuration)
    before = configuration.read_bytes()
    agent.state.mkdir(parents=True, exist_ok=True)
    (agent.state / marker).touch()
    applied = {'success': True, 'phase': 'applied', 'confirmed': True}
    rotated = {'success': True, 'action': 'rotate', 'phase': 'applied'}
    with mock.patch('relay_trust_sync.TrustSynchronizer.sync', return_value=applied) as sync, \
            mock.patch.object(agent, 'rotation_backend'), \
            mock.patch('rotation_transaction.rotate', return_value=rotated) as rotate:
        assert agent.apply('trust')['phase'] == 'inactive'
        sync.assert_not_called()
        assert agent.apply('rotate') == rotated
    sync.assert_called_once()
    rotate.assert_called_once()
    assert configuration.read_bytes() == before and (agent.state / marker).exists()


@pytest.mark.parametrize('phase', ['prepared', 'received'])
def test_pending_rotation_defers_trust_cron_before_native_or_network_changes(case, phase):
    case.agent.state.mkdir(parents=True, exist_ok=True)
    (case.agent.state / 'rotation.json').write_text('private retained journal')
    with mock.patch('rotation.RotationJournal.pending_phase', return_value=phase) as pending, \
            mock.patch.object(case.agent, 'recover_trust') as recovery, \
            mock.patch.object(case.agent, 'trust_transaction') as transaction:
        result = case.agent.apply('trust')
    assert result['success'] is True and result['phase'] == 'rotation_pending'
    assert result['confirmed'] is False and phase not in result['message']
    pending.assert_called_once_with()
    recovery.assert_not_called()
    transaction.assert_not_called()


def test_invalid_pending_rotation_blocks_trust_cron_before_changes(case):
    from rotation import RotationError
    case.agent.state.mkdir(parents=True, exist_ok=True)
    (case.agent.state / 'rotation.json').write_text('invalid journal')
    with mock.patch('rotation.RotationJournal.pending_phase', side_effect=RotationError('private diagnostic')), \
            mock.patch.object(case.agent, 'recover_trust') as recovery:
        result = case.agent.apply('trust')
    assert result['success'] is False and 'private diagnostic' not in str(result)
    recovery.assert_not_called()
