"""Exercise boot, direct startup and pending watchdog fences with real journals."""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from unittest import mock

import pytest

from test_relay_trust_transaction import transaction, example, SimulatedPowerLoss
from relay_trust_recover import recover_pending, startup_allowed

ROOT = Path(__file__).resolve().parents[1]


def watchdog_class():
    pytest.importorskip('fcntl')
    import watchdog
    return watchdog.Watchdog


def configuration(transaction):
    path = transaction.config/'fixture-config.xml'
    path.write_text('<opnsense><OPNsense><NetHubAgent><enabled>1</enabled></NetHubAgent></OPNsense></opnsense>')
    return path


def guard(transaction, path, controlled=False):
    return startup_allowed(transaction.config, path, backend=transaction.backend,
                           controlled=controlled, openssl=transaction.openssl)


@pytest.mark.parametrize('phase', ['prepared', 'written'])
def test_pending_guard_never_accepts_prepared_and_narrowly_permits_written_reload(transaction, phase):
    path = configuration(transaction)
    write = transaction._write
    def die(value):
        write(value)
        if value['phase'] == phase: raise SimulatedPowerLoss()
    transaction._write = die
    with pytest.raises(SimulatedPowerLoss): transaction.apply(example())
    assert guard(transaction, path) is False
    assert guard(transaction, path, controlled=True) is (phase == 'written')
    assert transaction.read()['phase'] == phase
    transaction._write = write
    transaction.recover()
    assert guard(transaction, path) is True


def test_direct_guard_checks_applied_binding_managed_ca_and_journal_integrity(transaction):
    path = configuration(transaction)
    transaction.apply(example())
    assert guard(transaction, path) is True
    transaction.backend.current['binding'] = 'b'*64
    assert guard(transaction, path, controlled=True) is False
    transaction.backend.current['binding'] = 'a'*64
    transaction.ca.write_text('unrelated public local material')
    assert guard(transaction, path, controlled=True) is False
    transaction.ca.write_text(example()['desired']['ca_pem'])
    transaction.path.write_bytes(b'{"phase":"applied"}')
    assert guard(transaction, path, controlled=True) is False


def test_legacy_no_journal_startup_and_empty_recovery_need_no_key_or_network(tmp_path):
    path = tmp_path/'configuration.xml'; path.write_text('<opnsense/>')
    assert startup_allowed(tmp_path, path) is True
    assert recover_pending(tmp_path, tmp_path/'state') == {'success': True, 'phase': 'idle'}
    assert not (tmp_path/'state').exists() and not (tmp_path/'gui-key').exists()


@pytest.mark.skipif(os.name == 'nt', reason='Native shared lock requires POSIX')
def test_boot_recovery_obeys_lock_and_restores_without_starting(transaction):
    import fcntl
    transaction.ca.unlink(); transaction.backend.fault = 'power_loss'
    with pytest.raises(SimulatedPowerLoss): transaction.apply(example())
    transaction.backend.fault = None
    state = transaction.config/'state'; state.mkdir(mode=0o700)
    path = state/'reconcile.lock'
    with path.open('a') as lock:
        path.chmod(0o600); fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert recover_pending(transaction.config, state, transaction.backend, lambda: True)['phase'] == 'busy'
    stops = []
    def stop(): stops.append(True); return True
    assert recover_pending(transaction.config, state, transaction.backend, stop)['phase'] == 'recovered'
    assert stops == [True] and not transaction.ca.exists()
    assert recover_pending(transaction.config, state, transaction.backend, stop)['phase'] == 'idle'
    assert not (transaction.config/'gui-key').exists()


@pytest.mark.parametrize('phase', ['prepared', 'written', 'invalid'])
def test_independent_watchdog_stops_and_never_rolls_back_pending_or_corrupt_trust(transaction, phase):
    Watchdog = watchdog_class()
    root = transaction.config/'watchdog-root'
    (root/'conf').mkdir(parents=True)
    (root/'conf/config.xml').write_text('<opnsense><OPNsense><NetHubAgent><enabled>1</enabled></NetHubAgent></OPNsense></opnsense>')
    transaction.apply(example())
    value = transaction.read(); value['phase'] = phase
    transaction.path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n')
    actions = []
    def run(args, **kwargs):
        actions.append(args[-1]); return subprocess.CompletedProcess(args, 0, '', '')
    watcher = Watchdog(root, run)
    watcher.config = transaction.config
    assert watcher.apply()['action'] == 'disabled'
    assert actions == ['onestatus', 'onestop']
    assert not watcher.journal.exists()


@pytest.mark.parametrize('phase', ['applied', 'rolled_back'])
def test_terminal_journal_does_not_disable_independent_watchdog(transaction, phase):
    Watchdog = watchdog_class()
    transaction.apply(example()); value = transaction.read(); value['phase'] = phase
    transaction.path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n')
    watcher = Watchdog(transaction.config)
    watcher.config = transaction.config
    assert watcher.trust_transaction_terminal() is True


@pytest.mark.skipif(os.name == 'nt', reason='Actual package hook shell is POSIX')
@pytest.mark.parametrize('guard_exit', [0, 1])
def test_actual_rc_prestart_guard_runs_before_frpc_validation(tmp_path, guard_exit):
    text = (ROOT/'src/usr/local/etc/rc.d/nethub_agent_frpc').read_text()
    body = re.search(r'nethub_agent_prestart\(\)\n\{(.*?)\n\}', text, re.S).group(1)
    state = tmp_path/'state'; state.mkdir()
    log = tmp_path/'log'
    program = tmp_path/'guard.py'; program.write_text('raise SystemExit('+str(guard_exit)+')\n')
    binary = tmp_path/'frpc'; event = tmp_path/'validated'
    binary.write_text('#!/bin/sh\ntouch '+shlex.quote(str(event))+'\n'); binary.chmod(0o755)
    config = tmp_path/'frpc.toml'; config.write_text('fixture')
    body = body.replace('/var/db/nethub-agent', str(state)).replace('/var/log/nethub-agent', str(log))
    body = body.replace('/usr/local/bin/python3.13 /usr/local/opnsense/scripts/nethub-agent/relay_trust_recover.py',
                        shlex.quote(sys.executable)+' '+shlex.quote(str(program)))
    script = tmp_path/'prestart.sh'
    script.write_text('set -eu\nprocname='+shlex.quote(str(binary))+'\nrequired_files='+shlex.quote(str(config))+
                      '\nprestart() {\n'+body+'\n}\nprestart\n')
    result = subprocess.run(['sh', str(script)], capture_output=True, timeout=10)
    assert (result.returncode == 0) is (guard_exit == 0)
    assert event.exists() is (guard_exit == 0)


def test_early_trust_hook_is_packaged_executable_before_gui_and_tunnel_start():
    hook = ROOT/'src/usr/local/etc/rc.syshook.d/early/14-nethub-agent-trust'
    command = shlex.split(next(line for line in hook.read_text().splitlines() if line.startswith('/usr/bin/timeout')))
    assert command[:10] == ['/usr/bin/timeout', '-k', '2', '35', '/usr/bin/lockf', '-sk', '-t', '0',
                           '/var/db/nethub-agent/reconcile.lock', '/usr/local/bin/python3.13']
    assert command[10:12] == ['/usr/local/opnsense/scripts/nethub-agent/relay_trust_recover.py', '--locked']
    assert 'usr/local/etc/rc.syshook.d/early/14-nethub-agent-trust' in (ROOT/'build.py').read_text()
