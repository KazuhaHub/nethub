#!/usr/local/bin/python3.13
"""Recover one stopped tunnel without importing the main agent implementation."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET


class Watchdog:
    def __init__(self, root=Path('/'), runner=subprocess.run):
        self.root, self.runner = root, runner
        self.state = root / 'var/db/nethub-agent'
        self.config = root / 'usr/local/etc/nethub-agent'
        self.journal = self.state / 'recovery.json'

    def run(self, args, **kwargs):
        return self.runner([str(value) for value in args], capture_output=True, text=True, timeout=30, **kwargs)

    def service(self, verb, recovery=False):
        command = ['/usr/sbin/service']
        if recovery:
            # service(8) clears its environment; -E takes an explicit assignment.
            command += ['-E', 'NETHUB_WATCHDOG_RECOVERY_ONCE=1']
        return self.run(command + ['nethub_agent_frpc', verb])

    def atomic(self, path, content):
        descriptor, name = tempfile.mkstemp(prefix='.watchdog-', dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, 'wb') as target:
                target.write(content)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def save(self, record):
        record['updated_at'] = datetime.now(timezone.utc).isoformat()
        self.atomic(self.journal, (json.dumps(record) + '\n').encode())

    def recover(self):
        model = ET.parse(self.root / 'conf/config.xml').find('OPNsense/NetHubAgent')
        inactive = model is None or model.findtext('enabled') != '1'
        inactive = inactive or any((self.state / marker).exists() for marker in ['disabled', 'stopped', 'revoked', 'uninstalling'])
        running = self.service('onestatus').returncode == 0
        if inactive:
            rc = self.root / 'etc/rc.conf.d'
            rc.mkdir(parents=True, exist_ok=True)
            self.atomic(rc / 'nethub_agent_frpc', b'nethub_agent_frpc_enable="NO"\n')
            if running and self.service('onestop').returncode:
                return {'success': False, 'action': 'stop_failed'}
            return {'success': True, 'action': 'disabled'}
        if running:
            return {'success': True, 'action': 'running'}
        if self.journal.exists():
            prior = json.loads(self.journal.read_text())
            if (not isinstance(prior, dict) or prior.get('version') != 1
                    or not isinstance(prior.get('rejected_sha256'), str)
                    or not re.fullmatch('[a-f0-9]{64}', prior['rejected_sha256'])
                    or not isinstance(prior.get('attempted'), bool)
                    or not isinstance(prior.get('abandoned'), bool)):
                return {'success': False, 'action': 'invalid_recovery_state'}
            # A different desired configuration must be validated by reconcile first.
            prior['abandoned'] = True
            self.save(prior)
            return {'success': False, 'action': 'already_attempted'}
        live = self.config / 'frpc.toml'
        if not live.is_file():
            return {'success': False, 'action': 'no_live_configuration'}
        record = {'version': 1, 'rejected_sha256': hashlib.sha256(live.read_bytes()).hexdigest(),
                  'attempted': False, 'abandoned': True}
        # Persist before replacing anything, so a crash cannot reset the retry budget.
        self.save(record)
        backup = self.config / 'frpc.toml.last-good'
        if not backup.is_file():
            return {'success': False, 'action': 'no_last_good'}
        binary = self.root / 'usr/local/opnsense/nethub-agent/bin/frpc'
        if self.run([binary, 'verify', '--strict_config=true', '-c', backup]).returncode:
            return {'success': False, 'action': 'invalid_last_good'}
        record['attempted'] = True
        self.save(record)
        self.atomic(live, backup.read_bytes())
        rc = self.root / 'etc/rc.conf.d'
        rc.mkdir(parents=True, exist_ok=True)
        self.atomic(rc / 'nethub_agent_frpc', b'nethub_agent_frpc_enable="YES"\n')
        started = self.service('onestart', recovery=True).returncode == 0
        running = started and self.service('onestatus').returncode == 0
        record['abandoned'] = not running
        self.save(record)
        return {'success': running, 'action': 'rollback' if running else 'rollback_failed'}

    def apply(self, locked=False):
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state.chmod(0o700)
        os.umask(0o077)
        with (self.state / 'reconcile.lock').open('a') as lock:
            try:
                if not locked:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'success': True, 'action': 'skipped'}
            try:
                return self.recover()
            except (OSError, ValueError, ET.ParseError, subprocess.SubprocessError):
                return {'success': False, 'action': 'watchdog_error'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--locked', action='store_true', help=argparse.SUPPRESS)
    result = Watchdog().apply(locked=parser.parse_args().locked)
    print(json.dumps(result))
