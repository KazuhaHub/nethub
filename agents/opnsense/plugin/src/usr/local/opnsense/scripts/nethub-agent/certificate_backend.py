"""Bounded native GUI operations and loopback TLS/HTTP confirmation."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess

from certificate_chain import ChainVerifier
from certificate_key import CertificateKeyError
from certificate_transaction import CertificatePreparationRequired


class NativeGuiError(Exception):
    """A fixed diagnostic without child output or native private entries."""


class NativeGuiBackend:
    """The caller holds reconcile.lock; boot rollback never starts the GUI."""

    def __init__(self, key_store, trusted_ca_file=None, boot=False, run=subprocess.run):
        self.trust = ChainVerifier(key_store, trusted_ca_file)
        self.boot = boot
        self.run = run
        self.script = Path(__file__).with_name('gui_certificate.php')

    def _call(self, action, request):
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            raise NativeGuiError('Native GUI certificate operations require root')
        if action not in ('prepare', 'install', 'check', 'rollback'):
            raise NativeGuiError('Unknown native GUI operation')
        try:
            body = json.dumps({'action': action, 'request': request}, separators=(',', ':')).encode('ascii')
            if len(body) > 16384:
                raise ValueError('Native GUI request exceeds its limit')
            result = self.run(['/usr/local/bin/php', str(self.script)], input=body, capture_output=True, timeout=5)
            if len(result.stdout) > 16384 or len(result.stderr) > 8192:
                raise ValueError('Native GUI reply exceeds its limit')
            value = json.loads(result.stdout)
            if not isinstance(value, dict):
                raise ValueError('Invalid native GUI reply')
            if value.get('success') is False and value.get('code') == 'alternate_hostname_required':
                raise CertificatePreparationRequired('alternate_hostname_required')
            if result.returncode or value.get('success') is not True or not isinstance(value.get('result'), dict):
                raise ValueError('Native GUI operation was not confirmed')
            fields = {'prepare': {'refid', 'native_hash', 'snapshot_sha256', 'port'},
                      'install': {'selected', 'changed'}, 'rollback': {'restored', 'changed'},
                      'check': {'selected', 'host', 'port', 'leaf_fingerprint'}}
            if set(value) != {'success', 'result'} or set(value['result']) != fields[action]:
                raise ValueError('Unexpected native GUI reply fields')
            return value['result']
        except CertificatePreparationRequired:
            raise
        except (OSError, ValueError, TypeError, UnicodeError, subprocess.SubprocessError):
            raise NativeGuiError('Native GUI certificate operation failed') from None

    @staticmethod
    def _identity(value):
        return {key: value[key] for key in ('nonce', 'snapshot_sha256', 'candidate_sha256')}

    def _restart(self):
        try:
            # No arguments: the native "renew" argument would create a new key.
            result = self.run(['/usr/local/etc/rc.restart_webgui'], capture_output=True, timeout=8)
            if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 16384:
                raise ValueError('Native GUI restart was not confirmed')
        except (OSError, ValueError, subprocess.SubprocessError):
            raise NativeGuiError('Native GUI restart failed; inspect pending certificate recovery') from None

    def prepare(self, nonce, digest, good):
        return self._call('prepare', {'nonce': nonce, 'candidate_sha256': digest, 'last_good': good})

    def install(self, value):
        if self.boot:
            raise NativeGuiError('Boot recovery cannot install a new certificate')
        result = self._call('install', self._identity(value))
        if result.get('selected') is not True or type(result.get('changed')) is not bool:
            raise NativeGuiError('Native GUI installation was not confirmed')
        if result['changed']:
            self._restart()
        return True

    def check(self, value):
        return self._call('check', self._identity(value)).get('selected') is True

    def rollback(self, value):
        try:
            result = self._call('rollback', self._identity(value))
        except NativeGuiError:
            # A native save can succeed before its reply/audit completion fails.
            # The fenced rollback is idempotent and can confirm that outcome.
            result = self._call('rollback', self._identity(value))
        if result.get('restored') is not True or type(result.get('changed')) is not bool:
            raise NativeGuiError('Native GUI rollback was not confirmed')
        if not self.boot:
            # A prior attempt may already have restored config but died during
            # restart. Confirm recovery with a fresh restart even when unchanged.
            self._restart()
        return True

    def probe(self, value):
        if self.boot:
            return False
        try:
            metadata = self._call('check', self._identity(value))
            host, port, fingerprint = (metadata.get(field) for field in ('host', 'port', 'leaf_fingerprint'))
            if (metadata.get('selected') is not True or not isinstance(host, str) or len(host) > 253
                    or not re.fullmatch(r'[a-z0-9]{8}(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', host)
                    or type(port) is not int or not 1 <= port <= 65535 or port != value['port']
                    or not isinstance(fingerprint, str) or not re.fullmatch('[a-f0-9]{64}', fingerprint)
                    or self.trust.trusted_ca_file is None):
                return False
            roots = self.trust._roots()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            # Load PEM with native file semantics, including legitimate UTF-8
            # comments, then refuse a trust-bundle change during context setup.
            context.load_verify_locations(cafile=str(self.trust.trusted_ca_file))
            if self.trust._roots() != roots:
                return False
            authority = host if port == 443 else host + ':' + str(port)
            with socket.create_connection(('127.0.0.1', port), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname=host) as peer:
                    if hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest() != fingerprint:
                        return False
                    peer.sendall(('HEAD / HTTP/1.1\r\nHost: ' + authority + '\r\nConnection: close\r\n\r\n').encode('ascii'))
                    with peer.makefile('rb') as response:
                        first = response.readline(4097)
                    return (len(first) <= 4096 and re.fullmatch(
                        rb'HTTP/1\.[01] (?:200|301|302|303|307|308|401) [^\r\n]*\r\n', first) is not None)
        except (NativeGuiError, CertificatePreparationRequired, CertificateKeyError,
                OSError, ValueError, TypeError, KeyError, UnicodeError):
            return False
