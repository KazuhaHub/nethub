"""Check package-owned scheduler entries and shared mutation locks."""
import configparser
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOCK = '/var/db/nethub-agent/reconcile.lock'


def test_package_cron_uses_system_format_and_absolute_commands():
    cron = ROOT / 'src/usr/local/etc/cron.d/nethub-agent'
    lines = [line for line in cron.read_text().splitlines() if line and not line.startswith('#')]
    assert len(lines) == 2
    for index, line in enumerate(lines):
        fields = shlex.split(line)
        assert fields[:6] == ['*' if index == 0 else '*/5', '*', '*', '*', '*', 'root']
        assert fields[6:12] == ['/usr/bin/lockf', '-sk', '-t', '0', LOCK, '/usr/local/bin/python3.13']
        assert fields[12].startswith('/usr/local/opnsense/scripts/nethub-agent/')
        assert '--locked' in fields
        assert fields[-3:] == ['>>', '/var/log/nethub-agent/scheduler.log', '2>&1']
    assert cron.read_bytes().endswith(b'\n')


def test_configd_mutations_take_the_same_lock():
    parser = configparser.ConfigParser(delimiters=(':',), interpolation=None)
    parser.read(ROOT / 'src/usr/local/opnsense/service/conf/actions.d/actions_nethub-agent.conf')
    for name in ['start', 'stop', 'restart', 'reconcile']:
        command = shlex.split(parser[name]['command'])
        assert command[:6] == ['/usr/bin/lockf', '-sk', '-t', '0', LOCK, '/usr/local/bin/python3.13']
        assert command[-2:] == ['--locked', name]


def test_boot_recreates_log_directory_before_output_redirection():
    script = (ROOT / 'src/usr/local/etc/rc.syshook.d/start/20-nethub-agent').read_text()
    directory = script.index('install -d -m 0700 /var/db/nethub-agent /var/log/nethub-agent')
    protected = script.index('chmod 0600 /var/log/nethub-agent/scheduler.log')
    command = script.index('/usr/bin/lockf')
    assert directory < protected < command


@pytest.mark.parametrize('record,allowed', [
    ({'version': 1, 'rejected_sha256': 'a' * 64, 'attempted': True, 'abandoned': False}, True),
    ({'version': 1, 'rejected_sha256': 'a' * 64, 'attempted': True, 'abandoned': True}, False),
    ({'version': 1, 'rejected_sha256': 'a' * 64, 'attempted': False, 'abandoned': False}, False),
    ({'version': 1, 'rejected_sha256': None, 'attempted': True, 'abandoned': False}, False),
    ({'version': 1, 'abandoned': False}, False),
    (None, False),
])
def test_rc_guard_rejects_abandoned_and_invalid_recovery_state(tmp_path, record, allowed):
    script = (ROOT / 'src/usr/local/etc/rc.d/nethub_agent_frpc').read_text()
    program = re.search(r"python3\.13 -c '\n(.*?)\n' >", script, re.S).group(1)
    state = tmp_path / 'recovery.json'
    state.write_text(json.dumps(record))
    program = program.replace('"/var/db/nethub-agent/recovery.json"', repr(str(state)))
    result = subprocess.run([sys.executable, '-c', program], capture_output=True, text=True)
    assert (result.returncode == 0) is allowed
