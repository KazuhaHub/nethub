"""Exercise the boot entry point against a local fenced transaction model."""
import json
import os
from pathlib import Path

import pytest

from test_certificate_transaction import transaction, Interrupted
from certificate_recover import recover_pending


def test_no_pending_directory_needs_no_key_network_or_state_files(tmp_path):
    state = tmp_path / 'state'
    assert recover_pending(tmp_path, state)['phase'] == 'idle'
    assert not state.exists() and not (tmp_path / 'gui-key').exists()


@pytest.mark.skipif(os.name == 'nt', reason='Boot mutation locking is POSIX; exercised on the appliance')
def test_boot_entry_recovers_without_an_enrolled_key_and_obeys_the_shared_lock(transaction):
    import fcntl
    journal, model, value, _ = transaction
    model.crash_after_install = True
    with pytest.raises(Interrupted):
        journal.apply(value)
    state = journal.directory.parent / 'boot-state'
    state.mkdir(mode=0o700)
    path = state / 'reconcile.lock'
    with path.open('a') as lock:
        path.chmod(0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert recover_pending(journal.directory.parent, state, model)['phase'] == 'busy'
    assert json.loads(journal.path.read_bytes())['phase'] == 'prepared'
    assert recover_pending(journal.directory.parent, state, model)['phase'] == 'rolled_back'
    assert model.native['ref'] == 'original' and not (journal.directory.parent / 'gui-key').exists()
    assert recover_pending(journal.directory.parent, state, model)['phase'] == 'idle'


def test_early_hook_precedes_start_and_uses_bounded_absolute_locked_recovery():
    import shlex
    root = Path(__file__).resolve().parents[1]
    hook = root / 'src/usr/local/etc/rc.syshook.d/early/15-nethub-agent-certificate'
    lines = hook.read_text().splitlines()
    command = shlex.split(next(line for line in lines if line.startswith('/usr/bin/timeout')))
    assert command[:10] == ['/usr/bin/timeout', '-k', '2', '20', '/usr/bin/lockf', '-sk', '-t', '0',
                            '/var/db/nethub-agent/reconcile.lock', '/usr/local/bin/python3.13']
    assert command[10:12] == ['/usr/local/opnsense/scripts/nethub-agent/certificate_recover.py', '--locked']
    assert command[-3:] == ['>>', '/var/log/nethub-agent/scheduler.log', '2>&1']
    assert 'usr/local/etc/rc.syshook.d/early/15-nethub-agent-certificate' in (root / 'build.py').read_text()
