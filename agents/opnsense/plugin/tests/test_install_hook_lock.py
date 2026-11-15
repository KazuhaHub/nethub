"""Exercise the real install hook's guard/lock ordering without native services."""
import fcntl
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time

import pytest


HOOK = Path(__file__).resolve().parents[1] / 'packaging/freebsd/+POST_INSTALL'


@pytest.fixture
def install_hook(tmp_path):
    root, commands = tmp_path / 'root', tmp_path / 'commands'
    commands.mkdir()
    state = root / 'var/db/nethub-agent'
    state.mkdir(parents=True)
    (state / 'uninstalling').touch()
    (root / 'var/lib/php/tmp').mkdir(parents=True)
    for name in ('scripts/firmware/register.php', 'mvc/script/run_migrations.php'):
        path = root / 'usr/local/opnsense' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#!/bin/sh\nexit 0\n')
        path.chmod(0o755)
    service = commands / 'service'
    service.write_text('#!/bin/sh\ntouch "$HOOK_TEST_STATE/configd-restarted"\nexit 0\n')
    service.chmod(0o755)
    lock = commands / 'lockf'
    lock.write_text('''#!/usr/bin/env python3
import fcntl, os, subprocess, sys, time
from pathlib import Path
args = sys.argv[1:]
seconds = 0
while args[0].startswith('-'):
    option = args.pop(0)
    if option == '-t':
        seconds = float(args.pop(0))
path, *command = args
if os.environ.get('HOOK_LOCK_FAIL') == '1':
    raise SystemExit(75)
deadline = time.monotonic() + seconds
with open(path, 'a') as handle:
    while True:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            Path(path).with_name('waiting').touch()
            if time.monotonic() >= deadline:
                raise SystemExit(75)
            time.sleep(.01)
    raise SystemExit(subprocess.run(command).returncode)
''')
    lock.chmod(0o755)
    agent = root / 'usr/local/opnsense/scripts/nethub-agent/agentctl.py'
    agent.parent.mkdir(parents=True, exist_ok=True)
    agent.write_text('''import fcntl, json, os, sys
from pathlib import Path
state = Path(os.environ['HOOK_TEST_STATE'])
held = False
with (state / 'reconcile.lock').open('a') as handle:
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        held = True
with (state / 'calls.jsonl').open('a') as output:
    output.write(json.dumps({'lock_held': held, 'guard_absent': not (state / 'uninstalling').exists(),
                             'arguments': sys.argv[1:]}) + '\\n')
raise SystemExit(int(os.environ.get('HOOK_RECONCILE_EXIT', '0')))
''')
    # Redirect only native paths to this disposable tree; execute the complete
    # package hook with actual shell/file operations and a real advisory lock.
    script = HOOK.read_text().replace('/usr/local', str(root / 'usr/local')).replace('/var/', str(root / 'var') + '/')
    script = script.replace(str(root / 'usr/local/bin/python3.13'), shlex.quote(sys.executable))
    script = script.replace('/usr/bin/lockf', shlex.quote(str(lock)))
    hook = tmp_path / 'install.sh'
    hook.write_text(script)
    env = {'PATH': str(commands) + os.pathsep + os.environ['PATH'], 'HOOK_TEST_STATE': str(state)}
    return hook, env, state


def test_guard_survives_contention_until_the_locked_reconcile_runs_once(install_hook):
    hook, env, state = install_hook
    for name in ('disabled', 'stopped', 'revoked'):
        (state / name).touch()
    with (state / 'reconcile.lock').open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        child = subprocess.Popen(['sh', str(hook)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not (state / 'waiting').exists():
                assert child.poll() is None, 'Install hook did not wait for the existing operation'
                assert time.monotonic() < deadline, 'Install hook did not reach the shared lock'
                time.sleep(.01)
            assert (state / 'uninstalling').exists(), 'Watchdog can see an unguarded stopped client before reconcile'
            assert not (state / 'calls.jsonl').exists()
            fcntl.flock(handle, fcntl.LOCK_UN)
            stdout, stderr = child.communicate(timeout=5)
            assert child.returncode == 0 and stderr == b''
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                child.communicate(timeout=5)
    calls = [json.loads(line) for line in (state / 'calls.jsonl').read_text().splitlines()]
    assert calls == [{'lock_held': True, 'guard_absent': True, 'arguments': ['--locked', 'reconcile']}]
    assert not (state / 'uninstalling').exists()
    assert all((state / name).exists() for name in ('disabled', 'stopped', 'revoked'))


def test_install_lock_failure_retains_guard_and_is_not_reported_as_success(install_hook):
    hook, env, state = install_hook
    result = subprocess.run(['sh', str(hook)], env=dict(env, HOOK_LOCK_FAIL='1'), capture_output=True, timeout=5)
    assert result.returncode != 0
    assert (state / 'uninstalling').exists()
    assert not (state / 'calls.jsonl').exists()
    assert b'NetHub Agent installed.' not in result.stdout


def test_rejected_reconcile_keeps_the_existing_package_install_policy(install_hook):
    hook, env, state = install_hook
    result = subprocess.run(['sh', str(hook)], env=dict(env, HOOK_RECONCILE_EXIT='1'), capture_output=True, timeout=5)
    assert result.returncode == 0
    calls = [json.loads(line) for line in (state / 'calls.jsonl').read_text().splitlines()]
    assert calls == [{'lock_held': True, 'guard_absent': True, 'arguments': ['--locked', 'reconcile']}]


@pytest.mark.skipif(not Path('/usr/bin/lockf').exists(), reason='Native FreeBSD lockf check')
def test_native_install_guard_and_reconcile_share_the_original_lock(install_hook):
    hook, env, state = install_hook
    shim = Path(env['PATH'].split(os.pathsep)[0]) / 'lockf'
    hook.write_text(hook.read_text().replace(shlex.quote(str(shim)), '/usr/bin/lockf'))
    with (state / 'reconcile.lock').open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        child = subprocess.Popen(['sh', str(hook)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not (state / 'configd-restarted').exists():
                assert child.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            assert (state / 'uninstalling').exists()
            assert not (state / 'calls.jsonl').exists()
            fcntl.flock(handle, fcntl.LOCK_UN)
            _, stderr = child.communicate(timeout=5)
            assert child.returncode == 0 and stderr == b''
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                child.communicate(timeout=5)
    assert [json.loads(line) for line in (state / 'calls.jsonl').read_text().splitlines()] == [
        {'lock_held': True, 'guard_absent': True, 'arguments': ['--locked', 'reconcile']}]
