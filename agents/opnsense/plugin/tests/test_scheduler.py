"""Check package-owned scheduler entries and shared mutation locks."""
import configparser
from pathlib import Path
import shlex

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
