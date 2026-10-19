#!/usr/local/bin/python3.13
"""Apply validated NetHub tunnel configuration without modifying config.xml."""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import syslog
import tempfile
import tomllib
import xml.etree.ElementTree as ET


class AgentError(Exception):
    """An operator-facing error that contains no command output or credentials."""


class Agent:
    def __init__(self, root=Path('/'), runner=subprocess.run):
        self.root = root
        self.run = runner
        self.config = root / 'usr/local/etc/nethub-agent'
        self.state = root / 'var/db/nethub-agent'
        self.live = self.config / 'frpc.toml'
        self.candidate = self.config / 'frpc.toml.candidate'
        self.backup = self.config / 'frpc.toml.last-good'
        self.binary = root / 'usr/local/opnsense/nethub-agent/bin/frpc'

    def command(self, args, timeout=30):
        return self.run([str(arg) for arg in args], capture_output=True, text=True, timeout=timeout)

    def service(self, verb):
        return self.command(['/usr/sbin/service', 'nethub_agent_frpc', verb])

    def running(self):
        return self.service('onestatus').returncode == 0

    def atomic(self, path, content):
        descriptor, name = tempfile.mkstemp(prefix='.nethub-', dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, 'wb') as target:
                target.write(content)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def enabled(self):
        model = ET.parse(self.root / 'conf/config.xml').find('OPNsense/NetHubAgent')
        return model is not None and model.findtext('enabled') == '1'

    def rc_enable(self, value):
        rc = self.root / 'etc/rc.conf.d'
        rc.mkdir(parents=True, exist_ok=True)
        self.atomic(rc / 'nethub_agent_frpc',
                    ('nethub_agent_frpc_enable="' + ('YES' if value else 'NO') + '"\n').encode())

    def record(self, success, message, action):
        result = {'success': success, 'message': message, 'action': action,
                  'updated_at': datetime.now(timezone.utc).isoformat()}
        self.atomic(self.state / 'state.json', (json.dumps(result) + '\n').encode())
        syslog.syslog(syslog.LOG_INFO if success else syslog.LOG_ERR,
                      'nethub-agent: ' + action + ': ' + message)
        return result

    def checked(self, result, message):
        if result.returncode:
            raise AgentError(message)

    def validate_candidate(self):
        settings = tomllib.loads(self.candidate.read_text())
        tls = settings.get('transport', {}).get('tls', {})
        if (tls.get('enable') is not True or not tls.get('serverName')
                or tls.get('trustedCaFile') != '/usr/local/etc/nethub-agent/relay-ca.pem'):
            raise AgentError('Relay certificate verification is required')
        if not (self.config / 'relay-ca.pem').is_file():
            raise AgentError('Install the relay CA before enabling the tunnel')
        if not settings.get('auth', {}).get('token'):
            raise AgentError('Relay authentication is missing')
        proxies = settings.get('proxies', [])
        if len(proxies) != 1 or not re.fullmatch(r'[a-z0-9-]{1,63}', proxies[0].get('subdomain', '')):
            raise AgentError('Device subdomain is missing or invalid')
        self.checked(self.command([self.binary, 'verify', '--strict_config=true', '-c', self.candidate]),
                     'frpc rejected the candidate configuration; live configuration was retained')

    def provision_enrollment_trust(self):
        model = ET.parse(self.root / 'conf/config.xml').find('OPNsense/NetHubAgent')
        encoded = model.findtext('relay_ca') if model is not None else None
        if not encoded:
            return
        from enrollment import validate_ca
        from protocol import ProtocolError
        try:
            content = base64.b64decode(encoded, validate=True)
            validate_ca(content.decode('ascii'))
        except (ValueError, UnicodeError, ProtocolError):
            raise AgentError('Stored relay trust is invalid') from None
        path = self.config / 'relay-ca.pem'
        if path.is_symlink():
            raise AgentError('Relay trust path is invalid')
        if path.exists() and path.read_bytes() != content:
            # Initial enrollment is supported here; CA replacement needs its authenticated transition.
            raise AgentError('Stored relay trust differs; review local trust before applying')
        if not path.exists():
            self.atomic(path, content)
        path.chmod(0o600)

    def enroll(self, request_file):
        from enrollment import consume_request, request_enrollment
        from protocol import ProtocolError
        try:
            request = consume_request(request_file, self.state / 'requests')
            tree = ET.parse(self.root / 'conf/config.xml')
            model = tree.find('OPNsense/NetHubAgent')
            if model is not None and model.findtext('device_id'):
                return {'success': True, 'enrolled': True}
            version = self.command(['/usr/local/sbin/opnsense-version', '-v'], timeout=5)
            self.checked(version, 'Could not read the platform version')
            product = json.loads((self.root / 'usr/local/opnsense/version/nethub-agent').read_text())
            host = tree.findtext('system/hostname', 'OPNsense')
            domain = tree.findtext('system/domain', '')
            hostname = host + ('.' + domain if domain else '')
            result = request_enrollment(request['origin'], request['token'], version.stdout.strip(),
                                        product['product_version'], hostname,
                                        cluster_hint=model is not None and model.findtext('cluster_hint') == '1')
            return {'success': True, 'assignment': result}
        except (AgentError, ProtocolError) as error:
            return {'success': False, 'message': str(error)}
        except (OSError, ValueError, ET.ParseError, subprocess.SubprocessError):
            return {'success': False, 'message': 'Enrollment failed; no local configuration was changed'}

    def reconcile_locked(self, force=False):
        if (any((self.state / marker).exists() for marker in ['disabled', 'stopped', 'revoked', 'uninstalling'])
                or not self.enabled()):
            self.rc_enable(False)
            if self.running():
                self.checked(self.service('onestop'), 'Could not stop the tunnel')
            return self.record(True, 'Tunnel is disabled', 'stop')
        self.candidate.unlink(missing_ok=True)
        self.provision_enrollment_trust()
        self.checked(self.command(['/usr/local/sbin/configctl', 'template', 'reload', 'OPNsense/NetHubAgent']),
                     'Template rendering failed; live configuration was retained')
        self.candidate.chmod(0o600)
        desired_hash = hashlib.sha256(self.candidate.read_bytes()).hexdigest()
        journal = self.state / 'recovery.json'
        if journal.exists():
            recovery = json.loads(journal.read_text())
            if (not isinstance(recovery, dict) or recovery.get('version') != 1
                    or not isinstance(recovery.get('rejected_sha256'), str)
                    or not re.fullmatch('[a-f0-9]{64}', recovery['rejected_sha256'])
                    or not isinstance(recovery.get('attempted'), bool)
                    or not isinstance(recovery.get('abandoned'), bool)):
                raise AgentError('Recovery state is invalid; operator review is required')
            if recovery.get('rejected_sha256') == desired_hash:
                self.candidate.unlink()
                return self.record(False, 'Desired configuration is quarantined after watchdog recovery', 'quarantined')
        self.validate_candidate()
        content = self.candidate.read_bytes()
        changed = not self.live.exists() or self.live.read_bytes() != content
        if changed:
            if self.live.exists():
                self.atomic(self.backup, self.live.read_bytes())
            os.replace(self.candidate, self.live)
        else:
            self.candidate.unlink()
        self.rc_enable(True)
        # Only a different, validated desired configuration can release quarantine.
        journal.unlink(missing_ok=True)
        active = self.running()
        action = 'restart' if active and (changed or force) else 'start' if not active else 'unchanged'
        if action != 'unchanged':
            self.checked(self.service('one' + action), 'Tunnel service action failed')
            if not self.running():
                raise AgentError('Tunnel process did not remain running')
        if changed:
            (self.state / 'rollback-attempt').unlink(missing_ok=True)
        return self.record(True, 'Configuration verified', action)

    def lifecycle_model(self):
        model = ET.parse(self.root / 'conf/config.xml').find('OPNsense/NetHubAgent')
        if model is None:
            raise AgentError('Enrollment configuration is unavailable')
        return model

    def stop_revoked(self):
        self.atomic(self.state / 'revoked', b'Enrollment inactive\n')
        self.rc_enable(False)
        if self.running():
            self.checked(self.service('onestop'), 'Could not stop the revoked tunnel')
        if self.running():
            raise AgentError('The tunnel did not stop; local review is required')

    def lifecycle_result(self, result):
        public = {key: result[key] for key in ('success', 'message', 'action', 'revoked', 'device_id') if key in result}
        public['updated_at'] = datetime.now(timezone.utc).isoformat()
        self.atomic(self.state / 'health.json', json.dumps(public).encode())
        return result

    def report_locked(self):
        from lifecycle import health_request, report_health
        from protocol import ProtocolError
        model = self.lifecycle_model()
        if not model.findtext('device_id'):
            return {'success': True, 'action': 'report', 'message': 'No enrollment to report'}
        version = self.command(['/usr/local/sbin/opnsense-version', '-v'], timeout=5)
        self.checked(version, 'Could not read the platform version')
        product = json.loads((self.root / 'usr/local/opnsense/version/nethub-agent').read_text())
        local = self.status()
        inactive = model.findtext('enabled') != '1' or any((self.state / name).exists() for name in ('disabled', 'revoked', 'uninstalling'))
        service_state = 'disabled' if inactive else local['status']
        if not inactive and isinstance(local['last_reconcile'], dict) and local['last_reconcile'].get('success') is False:
            service_state = 'error'
        try:
            body = health_request(model.findtext('device_id'), version.stdout.strip(), product['product_version'], service_state, local['last_reconcile'])
            reply = report_health(model.findtext('console_url'), model.findtext('device_secret'), body)
        except ProtocolError:
            raise AgentError('Device health report failed; check enrollment and console connectivity') from None
        if reply['revoked']:
            self.stop_revoked()
        return self.lifecycle_result({'success': True, 'action': 'report', 'revoked': reply['revoked'], 'message': 'Device health acknowledged'})

    def unenroll_locked(self):
        from lifecycle import request_removal
        from protocol import ProtocolError
        model = self.lifecycle_model()
        device_id = model.findtext('device_id')
        if not device_id:
            return {'success': True, 'action': 'unenroll', 'device_id': '', 'revoked': True}
        # Stop first and retain credentials until the server confirms removal, allowing retry.
        self.stop_revoked()
        try:
            request_removal(model.findtext('console_url'), model.findtext('device_secret'), device_id)
        except ProtocolError:
            raise AgentError('Tunnel stopped; server removal is unconfirmed. Retry Remove enrollment') from None
        self.atomic(self.state / 'unenroll-confirmed.json', json.dumps({'device_id': device_id, 'revoked': True}).encode())
        return {'success': True, 'action': 'unenroll', 'device_id': device_id, 'revoked': True}

    def forget_locked(self):
        model = self.lifecycle_model()
        if model.findtext('enabled') == '1' or any(model.findtext(key) for key in ('device_id', 'device_secret', 'frp_token', 'domain_claim')):
            raise AgentError('Native configuration must be cleared before removing runtime credentials')
        self.stop_revoked()
        paths = [self.live, self.candidate, self.backup, self.config / 'relay-ca.pem']
        paths += [self.state / name for name in ('state.json', 'recovery.json', 'rollback-attempt', 'health.json', 'unenroll-confirmed.json', 'stopped', 'revoked')]
        for path in paths:
            if path.is_symlink():
                raise AgentError('Runtime credential path needs local review')
            path.unlink(missing_ok=True)
        return {'success': True, 'action': 'forget', 'message': 'Enrollment removed'}

    def apply(self, action, locked=False):
        for directory in [self.config, self.state]:
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
        os.umask(0o077)
        with (self.state / 'reconcile.lock').open('a') as lock:
            try:
                if not locked:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'success': False, 'message': 'Another service operation is running', 'action': 'busy'}
            try:
                if action == 'report':
                    return self.report_locked()
                if action == 'unenroll':
                    return self.unenroll_locked()
                if action == 'forget':
                    return self.forget_locked()
                if action == 'stop':
                    self.atomic(self.state / 'stopped', b'Operator stop\n')
                elif action in ('start', 'restart'):
                    (self.state / 'stopped').unlink(missing_ok=True)
                return self.reconcile_locked(force=action == 'restart')
            except AgentError as error:
                if action in ('report', 'unenroll', 'forget'):
                    return self.lifecycle_result({'success': False, 'message': str(error), 'action': action})
                return self.record(False, str(error), 'error')
            except (OSError, ValueError, ET.ParseError, subprocess.SubprocessError):
                if action in ('report', 'unenroll', 'forget'):
                    return self.lifecycle_result({'success': False, 'message': 'Device operation failed; local settings were retained', 'action': action})
                # Child output can include credentials or complete configuration lines.
                return self.record(False, 'Service operation failed; review local configuration and CA', 'error')

    def status(self):
        try:
            state = json.loads((self.state / 'state.json').read_text())
        except (OSError, ValueError):
            state = None
        try:
            health = json.loads((self.state / 'health.json').read_text())
            health = {key: value for key, value in health.items() if key in ('success', 'message', 'action', 'revoked', 'updated_at')}
        except (OSError, ValueError, AttributeError):
            health = None
        return {'status': 'running' if self.running() else 'stopped', 'last_reconcile': state,
                'log': self.log_tail(),
                'disabled': (self.state / 'disabled').exists(),
                'revoked': (self.state / 'revoked').exists(),
                'operator_stopped': (self.state / 'stopped').exists(), 'last_report': health}

    def log_tail(self):
        try:
            # Do not expose logs unless all currently stored credentials can be redacted.
            model = ET.parse(self.root / 'conf/config.xml').find('OPNsense/NetHubAgent')
            secrets = [model.findtext(name) for name in ['device_secret', 'frp_token', 'domain_claim']]
            with (self.root / 'var/log/nethub-agent/frpc.log').open('rb') as source:
                source.seek(0, os.SEEK_END)
                source.seek(max(0, source.tell() - 8192))
                text = source.read().decode('utf-8', errors='replace')
            for value in sorted((value for value in secrets if value), key=len, reverse=True):
                text = text.replace(value, '[redacted]')
            events = []
            for line in text.splitlines()[-10:]:
                for marker, event in [
                    ('login to server success', 'Relay login succeeded'),
                    ('login to the server failed', 'Relay login failed'),
                    ('start proxy success', 'Proxy registration succeeded'),
                    ('start error', 'Proxy registration failed'),
                    ('control writer is closing', 'Control connection closed'),
                    ('reconnect', 'Reconnect activity'),
                ]:
                    if marker in line.lower():
                        events.append(event)
                        break
            # Return recognized events, not arbitrary lines that could contain former credentials.
            return '\n'.join(events)
        except (OSError, ET.ParseError, AttributeError):
            return ''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--locked', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--request-file', help=argparse.SUPPRESS)
    parser.add_argument('action', choices=['reconcile', 'status', 'start', 'stop', 'restart',
                                          'enroll', 'unenroll', 'report', 'forget', 'rotate'])
    arguments = parser.parse_args()
    action = arguments.action
    if action == 'enroll':
        if not arguments.request_file:
            result = {'success': False, 'message': 'Private enrollment request is required'}
        else:
            def timed_out(signum, frame):
                from protocol import ProtocolError
                raise ProtocolError('Console enrollment timed out')
            previous = signal.signal(signal.SIGALRM, timed_out)
            signal.setitimer(signal.ITIMER_REAL, 25)
            try:
                result = Agent().enroll(arguments.request_file)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)
    elif action in ('report', 'unenroll'):
        def timed_out(signum, frame):
            raise AgentError('Device operation timed out; inspect status before retrying')
        previous = signal.signal(signal.SIGALRM, timed_out)
        signal.setitimer(signal.ITIMER_REAL, 25)
        try:
            result = Agent().apply(action, locked=arguments.locked)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    elif action == 'rotate':
        result = {'success': False, 'message': 'Not implemented'}
    else:
        agent = Agent()
        result = agent.status() if action == 'status' else agent.apply(action, locked=arguments.locked)
    print(json.dumps(result))
    return 1 if result.get('success') is False else 0


if __name__ == '__main__':
    sys.exit(main())
