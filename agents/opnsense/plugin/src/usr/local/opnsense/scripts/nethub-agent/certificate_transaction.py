"""Durable GUI apply/recovery ordering; no native adapter is enabled here."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time

from certificate_key import KeyStore


class CertificateTransactionError(Exception):
    """A fixed diagnostic without native snapshots or child-process output."""


class CertificatePreparationRequired(CertificateTransactionError):
    """A local prerequisite selected from a closed set of public messages."""

    def __init__(self, code):
        if code != 'alternate_hostname_required':
            raise ValueError('Unknown certificate prerequisite')
        self.code = code
        super().__init__('Add the assigned host to native Alternate Hostnames before applying a GUI certificate')


class CertificateTransaction:
    """The caller holds reconcile.lock and has independently verified delivery.

    The native backend prepares a private immutable snapshot without changing
    configuration. install/rollback must fence the exact owned entry/certref,
    preserve unrelated fields and make their configuration writes durable.
    check/probe return only literal True on success; snapshot keys never cross
    the backend's public response boundary. Recovery never needs network/key
    creation, and runs even when enrollment is disabled or removed.
    """

    FIELDS = {'version', 'phase', 'nonce', 'snapshot_sha256', 'candidate_sha256', 'issued_sha256',
              'device_id', 'generation_id', 'generation', 'refid', 'native_hash',
              'port', 'attempts', 'retry_after', 'last_good', 'retired'}
    GOOD = {'device_id', 'generation_id', 'generation', 'refid', 'native_hash', 'candidate_sha256', 'issued_sha256'}

    def __init__(self, directory, backend, clock=time.time):
        self.directory = Path(directory)
        self.path = self.directory / 'transaction.json'
        self.backend = backend
        self.clock = clock
        self.files = KeyStore(self.directory.parent / 'gui-key')

    @staticmethod
    def _hex(value, length):
        return isinstance(value, str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', value) is not None

    @classmethod
    def _identity(cls, value):
        uuid = r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
        return (isinstance(value, dict) and cls.GOOD <= value.keys()
                and all(isinstance(value.get(key), str) and re.fullmatch(uuid, value[key]) for key in ['device_id', 'generation_id'])
                and type(value['generation']) is int and 1 <= value['generation'] <= 2147483647
                and cls._hex(value['refid'], 13) and cls._hex(value['native_hash'], 64)
                and cls._hex(value['candidate_sha256'], 64) and cls._hex(value['issued_sha256'], 64))

    @classmethod
    def _validate(cls, value):
        if (not isinstance(value, dict) or set(value) != cls.FIELDS or not cls._identity(value)
                or type(value['version']) is not int or value['version'] != 1
                or value['phase'] not in ('prepared', 'written', 'applied', 'rolled_back', 'removing')
                or not cls._hex(value['nonce'], 32) or not cls._hex(value['snapshot_sha256'], 64)
                or type(value['port']) is not int or not 1 <= value['port'] <= 65535
                or type(value['attempts']) is not int or not 1 <= value['attempts'] <= 3
                or type(value['retry_after']) is not int or not 0 <= value['retry_after'] <= 253402300799
                or value['last_good'] is not None and (
                    not cls._identity(value['last_good']) or set(value['last_good']) != cls.GOOD
                    or value['last_good']['device_id'] != value['device_id'])):
            raise ValueError('Invalid certificate apply journal')
        retired = value['retired']
        if (not isinstance(retired, list) or len(retired) > 8
                or any(not isinstance(item, dict) or set(item) != {'nonce', 'sha256'}
                       or not cls._hex(item['nonce'], 32) or not cls._hex(item['sha256'], 64)
                       or item['nonce'] == value['nonce'] for item in retired)
                or len({item['nonce'] for item in retired}) != len(retired)):
            raise ValueError('Invalid retired snapshot journal')
        return value

    def _directory(self, create=False):
        if self.directory.absolute() != self.directory.resolve():
            raise ValueError('Unsafe certificate apply directory')
        self.files._protected(self.directory.parent, directory=True)
        if create:
            self.directory.mkdir(mode=0o700, exist_ok=True)
            self.files._sync(self.directory.parent)
        self.files._protected(self.directory, directory=True)

    def _read(self):
        if not self.directory.exists() and not self.directory.is_symlink():
            return None
        self._directory()
        if not self.path.exists() and not self.path.is_symlink():
            return None
        info = self.files._protected(self.path)
        if not 1 <= info.st_size <= 8192:
            raise ValueError('Invalid certificate apply journal size')
        raw = self.path.read_bytes()
        value = self._validate(json.loads(raw))
        if KeyStore._encoded(value) != raw:
            raise ValueError('Ambiguous certificate apply journal')
        return value

    def _write(self, value):
        self._validate(value)
        self._directory(create=True)
        if self.path.exists() or self.path.is_symlink():
            self.files._protected(self.path)
        descriptor, name = tempfile.mkstemp(prefix='.transaction-', dir=self.directory)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                os.chmod(temporary, 0o600)
                stream.write(KeyStore._encoded(value))
                stream.flush()
                os.fsync(stream.fileno())
            self.files._protected(temporary)
            os.replace(temporary, self.path)
            self.files._sync(self.directory)
        finally:
            temporary.unlink(missing_ok=True)

    def _snapshot(self, value):
        path = self.directory / ('snapshot-' + value['nonce'] + '.json')
        info = self.files._protected(path)
        if not 1 <= info.st_size <= 1048576:
            raise ValueError('Invalid private native snapshot size')
        with path.open('r+b') as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('Private native snapshot changed')
            raw = stream.read(1048577)
            if len(raw) > 1048576 or hashlib.sha256(raw).hexdigest() != value['snapshot_sha256']:
                raise ValueError('Private native snapshot differs')
            # File and containing directory must survive before configuration
            # can change. Snapshot contents never leave the local process.
            os.fsync(stream.fileno())
        self.files._sync(self.directory)

    def _prune(self, value):
        """Unlink only exact snapshots named in the durable replacement journal."""
        if not value['retired']:
            return value
        for item in value['retired']:
            path = self.directory / ('snapshot-' + item['nonce'] + '.json')
            if path.exists() or path.is_symlink():
                self._snapshot({'nonce': item['nonce'], 'snapshot_sha256': item['sha256']})
                path.unlink()
                self.files._sync(self.directory)
        value = dict(value, retired=[])
        self._write(value)
        return value

    @staticmethod
    def _public(value, phase=None):
        return {'success': True, 'action': 'certificate', 'phase': phase or value['phase'],
                'generation': value['generation'], 'message': {
                    'applied': 'GUI certificate application verified',
                    'rolled_back': 'Previous GUI configuration restored; certificate retry is delayed',
                    'retry_wait': 'GUI certificate retry is delayed',
                    'retry_exhausted': 'GUI certificate retry budget is exhausted; local review is required',
                }[phase or value['phase']]}

    def recover(self):
        """Restore only a pending transaction, including before GUI boot starts."""
        try:
            value = self._read()
            if value is None or value['phase'] not in ('prepared', 'written'):
                return None
            self._snapshot(value)
            if self.backend.rollback(value) is not True:
                raise ValueError('Native rollback not confirmed')
            value = dict(value, phase='rolled_back', retry_after=int(self.clock()) + 300)
            self._write(value)
            return self._public(value)
        except Exception:
            raise CertificateTransactionError('GUI certificate application needs local recovery; tunnel configuration was retained') from None

    def forget(self):
        """Clear known runtime snapshots after native enrollment fields are cleared.

        A durable removing marker makes deletion retryable after any unlink.
        The installed independent native certificate/key is never removed.
        """
        try:
            self.recover()
            value = self._read()
            if value is None:
                if self.directory.exists() or self.directory.is_symlink():
                    self._directory()
                    if any(self.directory.iterdir()):
                        raise ValueError('Unknown runtime artifacts need review')
                    self.directory.rmdir()
                    self.files._sync(self.directory.parent)
                return
            references = [{'nonce': value['nonce'], 'sha256': value['snapshot_sha256']}, *value['retired']]
            known = {'transaction.json', *(('snapshot-' + item['nonce'] + '.json') for item in references)}
            if {path.name for path in self.directory.iterdir()} - known:
                raise ValueError('Unknown runtime artifacts need review')
            if value['phase'] != 'removing':
                for item in references:
                    path = self.directory / ('snapshot-' + item['nonce'] + '.json')
                    if path.exists() or path.is_symlink():
                        self._snapshot({'nonce': item['nonce'], 'snapshot_sha256': item['sha256']})
                value = dict(value, phase='removing')
                self._write(value)
            for item in references:
                path = self.directory / ('snapshot-' + item['nonce'] + '.json')
                if path.exists() or path.is_symlink():
                    self._snapshot({'nonce': item['nonce'], 'snapshot_sha256': item['sha256']})
                    path.unlink()
                    self.files._sync(self.directory)
            if self._read() != value:
                raise ValueError('Runtime removal journal changed')
            self.path.unlink()
            self.files._sync(self.directory)
            self.directory.rmdir()
            self.files._sync(self.directory.parent)
        except Exception:
            raise CertificateTransactionError('GUI certificate runtime cleanup needs local review; native certificates were retained') from None

    def apply(self, verified):
        """Apply an already verified, protected staged delivery through a backend."""
        prepared = False
        try:
            self.recover()
            self._directory(create=True)
            candidate = self.directory.parent / 'gui-certificate.json'
            info = self.files._protected(candidate)
            encoded = KeyStore._encoded(verified)
            if not 1 <= info.st_size <= 65536 or candidate.read_bytes() != encoded:
                raise ValueError('Verified candidate changed')
            digest = hashlib.sha256(encoded).hexdigest()
            issued = verified['issued']
            material = hashlib.sha256(KeyStore._encoded(issued)).hexdigest()
            previous = self._read()
            if previous is not None:
                if previous['phase'] == 'removing':
                    raise ValueError('Runtime removal must finish before applying a certificate')
                previous = self._prune(previous)
                if previous['device_id'] != verified['device_id']:
                    raise ValueError('Apply ownership belongs to another enrollment')
                if (issued['generation'] < previous['generation']
                        or issued['generation'] == previous['generation'] and previous['issued_sha256'] != material
                        or issued['generation'] != previous['generation'] and issued['generation_id'] == previous['generation_id']):
                    raise ValueError('Apply generation would regress or change identity')
                if previous['issued_sha256'] == material:
                    if previous['phase'] == 'applied':
                        self._snapshot(previous)
                        if self.backend.check(previous) is not True or self.backend.probe(previous) is not True:
                            raise ValueError('Applied certificate no longer matches the GUI')
                        return self._public(previous)
                    if previous['attempts'] >= 3:
                        return self._public(previous, 'retry_exhausted')
                    if self.clock() < previous['retry_after']:
                        return self._public(previous, 'retry_wait')
            good = ({key: previous[key] for key in self.GOOD} if previous and previous['phase'] == 'applied'
                    else previous['last_good'] if previous else None)
            # Interrupted preparation can leave an unreferenced private file.
            # Bound accumulation without deleting material of unknown ownership.
            if len(list(self.directory.glob('snapshot-*.json'))) >= 8:
                raise ValueError('Private snapshot storage needs local review')
            nonce = secrets.token_hex(16)
            summary = self.backend.prepare(nonce, digest, good)
            if not isinstance(summary, dict) or set(summary) != {'refid', 'native_hash', 'snapshot_sha256', 'port'}:
                raise ValueError('Invalid native preparation response')
            value = dict(summary, version=1, phase='prepared', nonce=nonce, candidate_sha256=digest,
                         issued_sha256=material,
                         device_id=verified['device_id'], generation_id=issued['generation_id'], generation=issued['generation'],
                         attempts=previous['attempts'] + 1 if previous and previous['issued_sha256'] == material else 1,
                         retry_after=0, last_good=good,
                         retired=[{'nonce': previous['nonce'], 'sha256': previous['snapshot_sha256']}] if previous else [])
            self._validate(value)
            self._snapshot(value)
            self._write(value)
            prepared = True
            value = self._prune(value)
            if self.backend.install(value) is not True:
                raise ValueError('Native installation not confirmed')
            value = dict(value, phase='written')
            self._write(value)
            if self.backend.probe(value) is not True or self.backend.check(value) is not True:
                raise ValueError('Native GUI did not confirm the selected certificate')
            value = dict(value, phase='applied')
            self._write(value)
            return self._public(value)
        except CertificatePreparationRequired as error:
            if prepared:
                self.recover()
                raise CertificateTransactionError('GUI certificate application failed; inspect the separate certificate status') from None
            raise CertificatePreparationRequired(error.code) from None
        except CertificateTransactionError:
            raise CertificateTransactionError('GUI certificate application needs local recovery; tunnel configuration was retained') from None
        except Exception:
            # Ordinary errors attempt bounded backend rollback. Process death
            # leaves prepared/written journal evidence for independent recovery.
            if prepared:
                self.recover()
            raise CertificateTransactionError('GUI certificate application failed; inspect the separate certificate status') from None
