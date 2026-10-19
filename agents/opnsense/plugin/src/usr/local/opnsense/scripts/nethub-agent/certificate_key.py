"""Keep the enrollment certificate key on the device, behind its mutation lock."""
import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from protocol import ProtocolError, gui_key_fingerprint


class CertificateKeyError(Exception):
    """A fixed diagnostic without command output, key data or submitted values."""


class KeyStore:
    """The caller holds reconcile.lock; this store never replaces an existing key."""

    def __init__(self, directory, openssl='/usr/bin/openssl'):
        self.directory = Path(directory)
        self.openssl = openssl

    def _protected(self, path, directory=False):
        info = path.lstat()
        wanted = 0o700 if directory else 0o600
        if (stat.S_ISLNK(info.st_mode) or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
                or (not directory and info.st_nlink != 1)
                or (hasattr(os, 'geteuid') and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != wanted))):
            raise CertificateKeyError('Certificate key storage needs local review')
        return info

    def _sync(self, directory):
        if os.name == 'nt':
            return
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _run(self, *arguments):
        result = subprocess.run([self.openssl, *map(str, arguments)], capture_output=True, timeout=3)
        if result.returncode or len(result.stdout) > 2048:
            raise CertificateKeyError('Could not validate the device certificate key')
        return result.stdout

    def _public(self, path):
        info = self._protected(path)
        if not 128 <= info.st_size <= 2048:
            raise CertificateKeyError('Device certificate key is missing or invalid')
        content = path.read_bytes()
        begin, end = b'-----BEGIN PRIVATE KEY-----\n', b'-----END PRIVATE KEY-----\n'
        if not content.startswith(begin) or not content.endswith(end):
            raise CertificateKeyError('Device certificate key is missing or invalid')
        encoded = base64.b64encode(base64.b64decode(b''.join(content[len(begin):-len(end)].splitlines()), validate=True))
        canonical = begin + b''.join(encoded[i:i+64]+b'\n' for i in range(0, len(encoded), 64)) + end
        if content != canonical:
            raise CertificateKeyError('Device certificate key encoding needs local review')
        self._run('pkey', '-in', path, '-passin', 'pass:', '-check', '-noout')
        der = self._run('pkey', '-in', path, '-passin', 'pass:', '-pubout', '-outform', 'DER')
        public = base64.urlsafe_b64encode(der).decode('ascii').rstrip('=')
        return {'version': 1, 'public_key': public, 'fingerprint': gui_key_fingerprint(public)}

    @staticmethod
    def _encoded(value):
        return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')

    def _metadata(self):
        path = self.directory / 'state.json'
        info = self._protected(path)
        if not 128 <= info.st_size <= 512:
            raise CertificateKeyError('Certificate key record needs local review')
        raw = path.read_bytes()
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {'version', 'public_key', 'fingerprint'}
                or type(value['version']) is not int or value['version'] != 1
                or value['fingerprint'] != gui_key_fingerprint(value['public_key']) or self._encoded(value) != raw):
            raise CertificateKeyError('Certificate key record needs local review')
        return value

    def _load(self):
        self._protected(self.directory, directory=True)
        if {p.name for p in self.directory.iterdir()} != {'key.pem', 'state.json'}:
            raise CertificateKeyError('Device certificate key is missing or invalid; restore it before retrying')
        value = self._metadata()
        if self._public(self.directory / 'key.pem') != value:
            raise CertificateKeyError('Device certificate key differs from its saved binding')
        return value

    def ensure(self):
        try:
            if self.directory.absolute() != self.directory.resolve():
                raise CertificateKeyError('Certificate key path needs local review')
            self._protected(self.directory.parent, directory=True)
            if self.directory.exists() or self.directory.is_symlink():
                return self._load()
            temporary = Path(tempfile.mkdtemp(prefix='.gui-key-', dir=self.directory.parent))
            try:
                key = temporary / 'key.pem'
                descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(descriptor)
                self._run('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key)
                value = self._public(key)
                with key.open('r+b') as source:
                    os.fsync(source.fileno())
                state = temporary / 'state.json'
                descriptor = os.open(state, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'wb') as output:
                    output.write(self._encoded(value))
                    output.flush()
                    os.fsync(output.fileno())
                self._sync(temporary)
                if self.directory.exists() or self.directory.is_symlink():
                    raise CertificateKeyError('Certificate key storage changed during enrollment')
                os.rename(temporary, self.directory)
                self._sync(self.directory.parent)
                return value
            finally:
                # Only unpublished files in our newly created private directory.
                # A process crash may retain that directory; it is never adopted.
                if temporary.exists():
                    for name in ('key.pem', 'state.json'):
                        path = temporary / name
                        if path.exists():
                            self._protected(path)
                            path.unlink()
                    temporary.rmdir()
        except CertificateKeyError:
            raise
        except (OSError, ValueError, UnicodeError, ProtocolError, subprocess.SubprocessError):
            raise CertificateKeyError('Device certificate key unavailable; restore it or review local enrollment') from None

    def forget(self):
        """Remove only the runtime key after confirmed removal/native field clearing.

        An installed GUI certificate/key belongs to the native certificate store;
        this method never reads, edits or removes that independent native entry.
        """
        try:
            if self.directory.absolute() != self.directory.resolve():
                raise CertificateKeyError('Certificate key path needs local review')
            self._protected(self.directory.parent, directory=True)
            if not self.directory.exists() and not self.directory.is_symlink():
                return
            self._protected(self.directory, directory=True)
            if {p.name for p in self.directory.iterdir()} - {'key.pem', 'state.json'}:
                raise CertificateKeyError('Certificate key storage needs local review')
            key, state = self.directory / 'key.pem', self.directory / 'state.json'
            if key.exists() or key.is_symlink():
                self._load()
                key.unlink()
                self._sync(self.directory)
            if state.exists() or state.is_symlink():
                self._metadata()
                state.unlink()
                self._sync(self.directory)
            self.directory.rmdir()
            self._sync(self.directory.parent)
        except CertificateKeyError:
            raise
        except (OSError, ValueError, UnicodeError, ProtocolError, subprocess.SubprocessError):
            raise CertificateKeyError('Certificate key cleanup needs local review') from None
