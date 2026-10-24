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
import time
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
        command = ['/usr/sbin/service']
        if getattr(self, '_trust_reload', False) and verb in ('onestart', 'onerestart'):
            command += ['-E', 'NETHUB_TRUST_APPLY_ONCE=1']
        return self.command(command + ['nethub_agent_frpc', verb])

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
        managed = model is not None and bool(model.findtext('relay_trust_state'))
        if not encoded and not managed:
            return
        from enrollment import validate_ca
        from protocol import ProtocolError
        try:
            content = base64.b64decode(encoded, validate=True)
            validate_ca(content.decode('ascii'))
            if managed:
                from relay_trust import verify_settings
                from relay_trust_backend import model_snapshot
                snapshot = model_snapshot(model.findtext('device_id'),
                    {'relay_ca': encoded, 'relay_trust_state': model.findtext('relay_trust_state')})
                verify_settings(snapshot, model.findtext('device_id'), model.findtext('server_name'), self.config)
        except (ValueError, UnicodeError, KeyError, TypeError, ProtocolError):
            if managed:
                self.rc_enable(False)
                if self.running():
                    self.checked(self.service('onestop'), 'Could not stop a tunnel with invalid managed trust')
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
        return managed

    def enroll(self, request_file, locked=False):
        try:
            for directory in (self.config, self.state):
                directory.mkdir(parents=True, exist_ok=True)
                directory.chmod(0o700)
            os.umask(0o077)
            with (self.state / 'reconcile.lock').open('a') as lock:
                if not locked:
                    deadline = time.monotonic() + 3
                    while True:
                        try:
                            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                return {'success': False, 'message': 'Another service operation is running', 'action': 'busy'}
                            time.sleep(min(0.1, remaining))
                return self.enroll_locked(request_file)
        except OSError:
            return {'success': False, 'message': 'Private enrollment storage is unavailable'}

    def enroll_locked(self, request_file):
        from enrollment import consume_request, request_enrollment
        from protocol import ProtocolError
        from certificate_key import CertificateKeyError, KeyStore
        try:
            request = consume_request(request_file, self.state / 'requests')
            tree = ET.parse(self.root / 'conf/config.xml')
            model = tree.find('OPNsense/NetHubAgent')
            if model is not None and model.findtext('device_id'):
                return {'success': True, 'enrolled': True}
            if model is not None and model.findtext('relay_trust_state'):
                raise AgentError('Former relay trust metadata cleanup is incomplete; retry removal first')
            remnants = [self.config / name for name in ('gui-apply', 'gui-request', 'gui-certificate.json', 'relay-trust')]
            if any(path.exists() or path.is_symlink() for path in remnants):
                raise AgentError('Previous enrollment runtime cleanup is incomplete; retry Remove enrollment before enrolling')
            version = self.command(['/usr/local/sbin/opnsense-version', '-v'], timeout=5)
            self.checked(version, 'Could not read the platform version')
            product = json.loads((self.root / 'usr/local/opnsense/version/nethub-agent').read_text())
            host = tree.findtext('system/hostname', 'OPNsense')
            domain = tree.findtext('system/domain', '')
            hostname = host + ('.' + domain if domain else '')
            key = KeyStore(self.config / 'gui-key').ensure()
            result = request_enrollment(request['origin'], request['token'], version.stdout.strip(),
                                        product['product_version'], hostname,
                                        cluster_hint=model is not None and model.findtext('cluster_hint') == '1',
                                        gui_public_key=key['public_key'])
            return {'success': True, 'assignment': result}
        except (AgentError, ProtocolError, CertificateKeyError) as error:
            return {'success': False, 'message': str(error)}
        except (OSError, ValueError, ET.ParseError, subprocess.SubprocessError):
            return {'success': False, 'message': 'Enrollment failed; no local configuration was changed'}

    def reconcile_locked(self, force=False, trust_recovery=True):
        if trust_recovery:
            self.recover_trust()
        if (any((self.state / marker).exists() for marker in ['disabled', 'stopped', 'revoked', 'uninstalling'])
                or not self.enabled()):
            self.rc_enable(False)
            if self.running():
                self.checked(self.service('onestop'), 'Could not stop the tunnel')
            return self.record(True, 'Tunnel is disabled', 'stop')
        self.candidate.unlink(missing_ok=True)
        managed_trust = self.provision_enrollment_trust()
        self.checked(self.command(['/usr/local/sbin/configctl', 'template', 'reload', 'OPNsense/NetHubAgent']),
                     'Template rendering failed; live configuration was retained')
        self.candidate.chmod(0o600)
        if managed_trust:
            # Include public CA identity in the existing desired/watchdog hash.
            # frpc configuration verification ignores this fixed comment.
            digest = hashlib.sha256((self.config / 'relay-ca.pem').read_bytes()).hexdigest()
            self.atomic(self.candidate, ('# nethub-relay-ca-sha256: ' + digest + '\n').encode() + self.candidate.read_bytes())
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

    def trust_transaction(self):
        from relay_trust_backend import NativeTrustBackend
        from relay_trust_transaction import TrustTransaction
        def quiesce():
            self.rc_enable(False)
            if self.running():
                self.checked(self.service('onestop'), 'Could not stop the tunnel for trust recovery')
            return not self.running()
        def reload():
            self._trust_reload = True
            try:
                return self.reconcile_locked(trust_recovery=False).get('success') is True
            finally:
                self._trust_reload = False
        return TrustTransaction(self.config, NativeTrustBackend(run=self.run, configuration=self.root/'conf/config.xml'),
                                quiesce, reload)

    def recover_trust(self):
        directory = self.config/'relay-trust'
        if not directory.exists() and not directory.is_symlink():
            return None
        from relay_trust_transaction import TrustTransactionError
        try:
            return self.trust_transaction().recover()
        except TrustTransactionError:
            raise AgentError('Pending relay trust recovery failed; tunnel startup is blocked') from None

    def trust_result(self, result):
        fields = ('success', 'phase', 'generation', 'confirmed', 'message')
        public = {key: result[key] for key in fields if key in result}
        public['action'] = 'trust'
        public['updated_at'] = datetime.now(timezone.utc).isoformat()
        self.atomic(self.state/'trust.json', (json.dumps(public)+'\n').encode())
        return public

    def trust_locked(self):
        from relay_trust_sync import TrustSynchronizer, TrustSyncError
        self.recover_trust()
        model = self.lifecycle_model()
        inactive = model.findtext('enabled') != '1' or any((self.state/name).exists()
            for name in ('disabled', 'stopped', 'revoked', 'uninstalling'))
        if inactive or not model.findtext('device_id') or not model.findtext('console_url'):
            return self.trust_result({'success': True, 'phase': 'inactive', 'confirmed': False})
        try:
            result = TrustSynchronizer(self.trust_transaction()).sync(model.findtext('console_url'),
                model.findtext('device_secret'), model.findtext('device_id'), model.findtext('server_name'))
        except TrustSyncError:
            raise AgentError('Relay trust synchronization failed; inspect trust and recovery status') from None
        return self.trust_result(result)

    def certificate_result(self, result):
        public = {key: result[key] for key in ('success', 'action', 'phase', 'message', 'generation', 'valid_until', 'confirmed', 'accepted_at') if key in result}
        public['updated_at'] = datetime.now(timezone.utc).isoformat()
        self.atomic(self.state / 'certificate.json', (json.dumps(public) + '\n').encode())
        return public

    def gui_transaction(self):
        from certificate_backend import NativeGuiBackend
        from certificate_key import KeyStore
        from certificate_transaction import CertificateTransaction
        return CertificateTransaction(self.config / 'gui-apply', NativeGuiBackend(KeyStore(self.config / 'gui-key')))

    def apply_gui_certificate(self, transaction):
        from certificate_chain import CertificateChainError, ChainVerifier
        from certificate_key import CertificateKeyError, KeyStore
        from certificate_transaction import CertificateTransactionError
        files = KeyStore(self.config / 'gui-key')
        path = self.config / 'gui-certificate.json'
        try:
            info = files._protected(path)
            if not 1 <= info.st_size <= 65536:
                raise ValueError('Invalid candidate size')
            raw = path.read_bytes()
            value = json.loads(raw)
            if KeyStore._encoded(value) != raw:
                raise ValueError('Ambiguous candidate')
            model = self.lifecycle_model()
            value = ChainVerifier(files).verify(value, model.findtext('device_id'), model.findtext('subdomain'), value['request'])
            if value['issued'] is None:
                raise ValueError('Pending material cannot be applied')
            result = transaction.apply(value)
        except (CertificateChainError, CertificateTransactionError) as error:
            raise AgentError(str(error)) from None
        except (CertificateKeyError, OSError, ValueError, KeyError, TypeError):
            raise AgentError('GUI certificate candidate needs local review') from None
        result['valid_until'] = value['issued']['valid_until']
        if result.get('phase') == 'applied':
            from certificate_protocol import report_applied, supports_application_reports
            from protocol import ProtocolError
            result['confirmed'] = False
            if not supports_application_reports(value['agent_protocol_version']):
                result.update(phase='applied_unconfirmed', message='GUI certificate verified locally; upgrade the console to confirm installation')
            else:
                try:
                    reply = report_applied(model.findtext('console_url'), model.findtext('device_secret'),
                                           model.findtext('device_id'), value['request'], value['issued'])
                    result.update(confirmed=True, accepted_at=reply['accepted_at'], message='GUI certificate verified locally and confirmed by the server')
                except (ProtocolError, OSError, ValueError):
                    # The applied journal is already durable. A later cycle
                    # rechecks it and retries reporting, without reinstalling.
                    result.update(phase='applied_unconfirmed', message='GUI certificate verified locally; server confirmation will retry')
        return result

    def certificate_locked(self):
        from certificate_key import KeyStore
        from certificate_sync import CertificateSyncError, CertificateSynchronizer
        from certificate_transaction import CertificateTransactionError
        transaction = self.gui_transaction()
        try:
            transaction.recover()
        except CertificateTransactionError as error:
            raise AgentError(str(error)) from None
        if (any((self.state / marker).exists() for marker in ['disabled', 'stopped', 'revoked', 'uninstalling'])
                or not self.enabled()):
            return self.certificate_result({'success': True, 'action': 'certificate', 'phase': 'inactive', 'message': 'GUI certificate synchronization is inactive'})
        model = self.lifecycle_model()
        if not model.findtext('device_id') or not model.findtext('console_url'):
            return self.certificate_result({'success': True, 'action': 'certificate', 'phase': 'inactive', 'message': 'No enrollment for GUI certificate synchronization'})
        try:
            result = CertificateSynchronizer(KeyStore(self.config / 'gui-key')).sync(
                model.findtext('console_url'), model.findtext('device_secret'), model.findtext('device_id'), model.findtext('subdomain'))
        except CertificateSyncError:
            raise AgentError('GUI certificate synchronization failed; tunnel and native GUI settings were retained') from None
        if result.get('phase') == 'verified':
            result = self.apply_gui_certificate(transaction)
        return self.certificate_result(result)

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
        if not model.findtext('device_id') or not model.findtext('console_url'):
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
            self.recover_trust()
            return {'success': True, 'action': 'unenroll', 'device_id': '', 'revoked': True}
        # Stop first and retain credentials until the server confirms removal, allowing retry.
        self.stop_revoked()
        # Rollback permits the stop/revocation marker and needs the old binding.
        self.recover_trust()
        try:
            request_removal(model.findtext('console_url'), model.findtext('device_secret'), device_id)
        except ProtocolError:
            raise AgentError('Tunnel stopped; server removal is unconfirmed. Retry Remove enrollment') from None
        self.atomic(self.state / 'unenroll-confirmed.json', json.dumps({'device_id': device_id, 'revoked': True}).encode())
        return {'success': True, 'action': 'unenroll', 'device_id': device_id, 'revoked': True}

    def forget_locked(self):
        from certificate_key import CertificateKeyError, KeyStore
        from certificate_sync import CertificateSynchronizer
        from certificate_transaction import CertificateTransactionError
        from relay_trust_transaction import TrustTransactionError
        model = self.lifecycle_model()
        if model.findtext('enabled') == '1' or any(model.findtext(key) for key in ('device_id', 'device_secret', 'frp_token', 'domain_claim', 'relay_trust_state')):
            raise AgentError('Native configuration must be cleared before removing runtime credentials')
        self.stop_revoked()
        try:
            directory = self.config/'relay-trust'
            if directory.exists() or directory.is_symlink():
                self.trust_transaction().forget()
            self.gui_transaction().forget()
            keys = KeyStore(self.config / 'gui-key')
            CertificateSynchronizer(keys).forget()
            keys.forget()
        except (CertificateKeyError, CertificateTransactionError, TrustTransactionError) as error:
            raise AgentError(str(error)) from None
        paths = [self.live, self.candidate, self.backup, self.config / 'relay-ca.pem']
        paths += [self.state / name for name in ('state.json', 'recovery.json', 'rollback-attempt', 'health.json', 'certificate.json', 'trust.json', 'unenroll-confirmed.json', 'stopped', 'revoked')]
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
                if action == 'certificate':
                    return self.certificate_locked()
                if action == 'trust':
                    return self.trust_locked()
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
                if action == 'trust':
                    return self.trust_result({'success': False, 'phase': 'error', 'message': str(error)})
                if action == 'certificate':
                    return self.certificate_result({'success': False, 'action': action, 'phase': 'error', 'message': str(error)})
                if action in ('report', 'unenroll', 'forget'):
                    return self.lifecycle_result({'success': False, 'message': str(error), 'action': action})
                return self.record(False, str(error), 'error')
            except (OSError, ValueError, ET.ParseError, subprocess.SubprocessError):
                if action == 'trust':
                    return self.trust_result({'success': False, 'phase': 'error', 'message': 'Relay trust operation failed; inspect local recovery status'})
                if action == 'certificate':
                    return self.certificate_result({'success': False, 'action': action, 'phase': 'error', 'message': 'GUI certificate synchronization failed; tunnel and native GUI settings were retained'})
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
        try:
            certificate = json.loads((self.state / 'certificate.json').read_text())
            certificate = {key: value for key, value in certificate.items() if key in ('success', 'action', 'phase', 'message', 'generation', 'valid_until', 'updated_at')}
        except (OSError, ValueError, AttributeError):
            certificate = None
        try:
            trust = json.loads((self.state/'trust.json').read_text())
            trust = {key: value for key, value in trust.items()
                     if key in ('success', 'action', 'phase', 'message', 'generation', 'confirmed', 'updated_at')}
        except (OSError, ValueError, AttributeError):
            trust = None
        return {'status': 'running' if self.running() else 'stopped', 'last_reconcile': state,
                'log': self.log_tail(),
                'disabled': (self.state / 'disabled').exists(),
                'revoked': (self.state / 'revoked').exists(),
                'operator_stopped': (self.state / 'stopped').exists(), 'last_report': health, 'gui_certificate': certificate,
                'relay_trust': trust}

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
                                          'enroll', 'unenroll', 'report', 'certificate', 'trust', 'forget', 'rotate'])
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
                result = Agent().enroll(arguments.request_file, locked=arguments.locked)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)
    elif action in ('report', 'unenroll', 'certificate', 'trust'):
        def timed_out(signum, frame):
            raise AgentError('Device operation timed out; inspect status before retrying')
        previous = signal.signal(signal.SIGALRM, timed_out)
        signal.setitimer(signal.ITIMER_REAL, 85 if action == 'trust' else 35 if action == 'certificate' else 25)
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
