#!/usr/local/bin/python3.13
"""Recover one stopped tunnel without importing the main agent implementation."""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
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

    def backup_trust_matches(self, live, backup):
        prefix = b'# nethub-relay-ca-sha256:'
        current = live.read_bytes()
        content = backup.read_bytes()
        match = re.match(rb'# nethub-relay-ca-sha256: ([a-f0-9]{64})\n', content)
        if match is None:
            return not current.startswith(prefix) and not content.startswith(prefix)
        for source in (live, backup):
            info = source.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                return False
        return hashlib.sha256(self.managed_ca()).hexdigest().encode() == match[1]

    def managed_ca(self):
        path = self.config / 'relay-ca.pem'
        parent = self.config.lstat()
        info = path.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077
                or self.config.resolve() != self.config or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or not 64 <= info.st_size <= 32768):
            raise ValueError('Managed trust path is invalid')
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('Managed trust file changed')
            material = stream.read(32769)
        if len(material) != info.st_size:
            raise ValueError('Managed trust size changed')
        return material

    def managed_trust_current(self, model):
        encoded = model.findtext('relay_trust_state') if model is not None else None
        if not encoded:
            return True
        try:
            if len(encoded) > 5500:
                return False
            raw = base64.b64decode(encoded, validate=True)
            state = json.loads(raw)
            fields = {'generation_id', 'generation', 'server_name', 'bundle_fingerprint', 'published_at', 'not_before', 'valid_until'}
            if (not isinstance(state, dict) or set(state) != fields or type(state['generation']) is not int
                    or not 1 <= state['generation'] <= 2147483647 or state['server_name'] != model.findtext('server_name')
                    or not isinstance(state['generation_id'], str)
                    or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', state['generation_id'])
                    or state['generation_id'] == '00000000-0000-0000-0000-000000000000'
                    or (json.dumps(state, sort_keys=True, separators=(',', ':'))+'\n').encode('ascii') != raw
                    or base64.b64encode(raw).decode('ascii') != encoded):
                return False
            stamps = []
            for name in ('not_before', 'valid_until', 'published_at'):
                value = state[name]
                if not isinstance(value, str) or len(value) != 27:
                    return False
                stamp = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
                if stamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ') != value:
                    return False
                stamps.append(stamp)
            if not stamps[0] <= datetime.now(timezone.utc) < stamps[1] or not stamps[0] <= stamps[2] < stamps[1]:
                return False
            encoded_ca = model.findtext('relay_ca')
            if not isinstance(encoded_ca, str) or len(encoded_ca) > 43692:
                return False
            material = base64.b64decode(encoded_ca, validate=True)
            if (base64.b64encode(material).decode('ascii') != encoded_ca or material != self.managed_ca()
                    or hashlib.sha256(b'nethub-relay-trust-v1:'+material).hexdigest() != state['bundle_fingerprint']):
                return False
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=material.decode('ascii'))
            roots = context.get_ca_certs()
            return (1 <= len(roots) <= 2 and max(ssl.cert_time_to_seconds(c['notBefore']) for c in roots) == stamps[0].timestamp()
                    and min(ssl.cert_time_to_seconds(c['notAfter']) for c in roots) == stamps[1].timestamp())
        except (OSError, ValueError, TypeError, KeyError, UnicodeError):
            return False

    def trust_transaction_terminal(self):
        directory = self.config/'relay-trust'
        if not directory.exists() and not directory.is_symlink():
            return True
        try:
            for path, mode, is_directory in ((self.config, 0o700, True), (directory, 0o700, True)):
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) != mode or path.resolve() != path):
                    return False
            if not any(directory.iterdir()):
                return True
            if {path.name for path in directory.iterdir()} != {'transaction.json'}:
                return False
            path = directory/'transaction.json'
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= 196608):
                return False
            with path.open('rb') as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    return False
                raw = stream.read(196609)
            value = json.loads(raw)
            fields = {'version', 'phase', 'binding', 'snapshot', 'before', 'after', 'before_ca', 'attempts', 'retry_after', 'receipt'}
            return (isinstance(value, dict) and set(value) == fields and type(value['version']) is int
                    and value['version'] == 1 and value['phase'] in ('applied', 'rolled_back')
                    and (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode('ascii') == raw)
        except (OSError, ValueError, TypeError, KeyError, UnicodeError):
            return False

    def recover(self):
        model = ET.parse(self.root / 'conf/config.xml').find('OPNsense/NetHubAgent')
        inactive = model is None or model.findtext('enabled') != '1'
        inactive = inactive or any((self.state / marker).exists() for marker in ['disabled', 'stopped', 'revoked', 'uninstalling'])
        inactive = inactive or not self.managed_trust_current(model)
        inactive = inactive or not self.trust_transaction_terminal()
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
        if not self.backup_trust_matches(live, backup):
            return {'success': False, 'action': 'last_good_trust_mismatch'}
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
