"""Durable public trust application ordering; the caller holds reconcile.lock."""
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

from certificate_key import KeyStore
from relay_trust import verify_settings
from relay_trust_backend import model_nodes, model_snapshot, _nodes
from relay_trust_protocol import applied_request, applied_response, _stamp


class TrustTransactionError(Exception):
    """A fixed diagnostic without configuration or backend output."""


class TrustTransaction:
    """Apply through an approved model backend and fenced managed file.

    quiesce must confirm the owned tunnel stopped without changing user intent.
    reload must validate/reconcile the current model/file and return literal True
    only on success. Recovery restores bytes and leaves a changed-CA tunnel
    stopped; it never treats expired old trust as a recovered connection.
    No device HTTP operation or application report is implicit in these methods.
    """

    FIELDS = {'version', 'phase', 'binding', 'snapshot', 'before', 'after', 'before_ca',
              'attempts', 'retry_after', 'receipt'}

    def __init__(self, config, backend, quiesce, reload, clock=time.time, openssl='/usr/bin/openssl'):
        self.config = Path(config)
        self.directory = self.config/'relay-trust'
        self.path = self.directory/'transaction.json'
        self.ca = self.config/'relay-ca.pem'
        self.backend, self.quiesce, self.reload = backend, quiesce, reload
        self.clock, self.openssl = clock, openssl

    def _protect(self, path, directory=False):
        info = path.lstat()
        if (not path.is_absolute() or path.resolve() != path
                or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
                or not directory and info.st_nlink != 1
                or hasattr(os, 'geteuid') and (info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600))):
            raise ValueError('Trust storage needs local review')
        return info

    def _directory(self, create=False):
        self._protect(self.config, directory=True)
        if create and not self.directory.exists() and not self.directory.is_symlink():
            self.directory.mkdir(mode=0o700)
            self.directory.chmod(0o700)
            self._sync(self.config)
        self._protect(self.directory, directory=True)

    @staticmethod
    def _sync(path):
        if os.name == 'nt':
            return
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _read_file(self, path, maximum):
        info = self._protect(path)
        if not 1 <= info.st_size <= maximum:
            raise ValueError('Invalid trust file size')
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('Trust file changed')
            raw = stream.read(maximum+1)
        if len(raw) != info.st_size:
            raise ValueError('Trust file changed')
        return raw

    def _atomic(self, path, raw):
        self._protect(path.parent, directory=True)
        if path.exists() or path.is_symlink():
            self._protect(path)
        descriptor, name = tempfile.mkstemp(prefix='.trust-', dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                os.chmod(temporary, 0o600)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            self._sync(path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _verify(self, snapshot, previous=None, historical=False):
        now = (_stamp(snapshot['desired']['not_before']) if historical
               else datetime.fromtimestamp(self.clock(), timezone.utc))
        return verify_settings(snapshot, snapshot['device_id'], snapshot['desired']['server_name'],
                               self.config, previous=previous, now=now, openssl=self.openssl)

    def _validate(self, value):
        if (not isinstance(value, dict) or set(value) != self.FIELDS or type(value['version']) is not int
                or value['version'] != 1 or value['phase'] not in ('prepared', 'written', 'applied', 'rolled_back')
                or not isinstance(value['binding'], str) or not re.fullmatch('[a-f0-9]{64}', value['binding'])
                or type(value['attempts']) is not int or not 1 <= value['attempts'] <= 3
                or type(value['retry_after']) is not int or not 0 <= value['retry_after'] <= 253402300799):
            raise ValueError('Invalid trust journal')
        snapshot = self._verify(value['snapshot'], historical=True)
        if snapshot != value['snapshot'] or _nodes(value['after']) != model_nodes(snapshot):
            raise ValueError('Trust journal snapshot changed')
        before = _nodes(value['before'])
        if before['relay_trust_state']:
            previous = model_snapshot(snapshot['device_id'], before)
            self._verify(previous, historical=True)
            self._verify(snapshot, previous=previous['desired'], historical=True)
        if value['before_ca'] is not None:
            if not isinstance(value['before_ca'], str) or len(value['before_ca']) > 43692:
                raise ValueError('Invalid previous trust file')
            raw = base64.b64decode(value['before_ca'], validate=True)
            if not 64 <= len(raw) <= 32768 or base64.b64encode(raw).decode() != value['before_ca']:
                raise ValueError('Invalid previous trust file')
            if value['before_ca'] != before['relay_ca']:
                raise ValueError('Previous model and trust file differed')
        if value['receipt'] is not None:
            desired = snapshot['desired']
            report = applied_request(snapshot['device_id'], desired['generation_id'], desired['generation'], desired['bundle_fingerprint'])
            if value['phase'] != 'applied' or applied_response(value['receipt'], report) != value['receipt']:
                raise ValueError('Invalid trust receipt')
        return value

    def read(self):
        try:
            if not self.directory.exists() and not self.directory.is_symlink():
                self._protect(self.config, directory=True)
                return None
            self._directory()
            if {item.name for item in self.directory.iterdir()} - {'transaction.json'}:
                raise ValueError('Unknown trust artifacts')
            if not self.path.exists() and not self.path.is_symlink():
                if any(self.directory.iterdir()):
                    raise ValueError('Unknown trust artifacts')
                return None
            raw = self._read_file(self.path, 196608)
            value = json.loads(raw)
            if KeyStore._encoded(value) != raw:
                raise ValueError('Ambiguous trust journal')
            return self._validate(value)
        except Exception:
            raise TrustTransactionError('Relay trust journal needs local review') from None

    def _write(self, value):
        self._validate(value)
        raw = KeyStore._encoded(value)
        if len(raw) > 196608:
            raise ValueError('Trust journal exceeds its limit')
        self._atomic(self.path, raw)

    def _ca_bytes(self):
        if not self.ca.exists() and not self.ca.is_symlink():
            return None
        return self._read_file(self.ca, 32768)

    def _replace_ca(self, value, rollback=False):
        before = base64.b64decode(value['before_ca']) if value['before_ca'] is not None else None
        after = value['snapshot']['desired']['ca_pem'].encode('ascii')
        current = self._ca_bytes()
        if current not in (before, after):
            raise ValueError('Managed trust changed outside this operation')
        target = before if rollback else after
        if current == target:
            if target is not None and os.name != 'nt':
                with self.ca.open('rb') as stream:
                    os.fsync(stream.fileno())
            self._sync(self.config)
            return
        if target is None:
            self.ca.unlink()
            self._sync(self.config)
        else:
            self._atomic(self.ca, target)

    @staticmethod
    def _public(value, phase=None):
        return {'success': value['phase'] == 'applied', 'phase': phase or value['phase'],
                'generation': value['snapshot']['desired']['generation'], 'confirmed': value['receipt'] is not None}

    def _current(self, value, after=True):
        actual = self.backend.read()
        return (actual['binding'] == value['binding'] and actual['device_id'] == value['snapshot']['device_id']
                and actual['server_name'] == value['snapshot']['desired']['server_name']
                and actual['nodes'] == value['after' if after else 'before'])

    def recover(self):
        """Restore a pending transaction locally; never start an expired old tunnel."""
        try:
            value = self.read()
            if value is None or value['phase'] not in ('prepared', 'written'):
                return None
            if value['before_ca'] != value['after']['relay_ca'] and self.quiesce() is not True:
                raise ValueError('Owned tunnel stop was not confirmed')
            self.backend.replace(value['binding'], value['before'], value['after'], rollback=True)
            self._replace_ca(value, rollback=True)
            if not self._current(value, after=False):
                raise ValueError('Native rollback was not confirmed')
            value = dict(value, phase='rolled_back', retry_after=int(self.clock())+300, receipt=None)
            self._write(value)
            return self._public(value)
        except Exception:
            raise TrustTransactionError('Relay trust recovery needs local review; tunnel startup must remain blocked') from None

    def apply(self, verified, binding=None):
        prepared = False
        try:
            self.recover()
            self._directory(create=True)
            previous = self.read()
            if binding is not None and self.backend.read()['binding'] != binding:
                raise ValueError('Enrollment changed during trust fetch')
            previous_desired = previous['snapshot']['desired'] if previous else None
            verified = self._verify(verified, previous=previous_desired)
            after = model_nodes(verified)
            if previous is not None:
                if previous['snapshot']['device_id'] != verified['device_id']:
                    raise ValueError('Trust journal belongs to another enrollment')
                if previous['snapshot']['desired'] == verified['desired']:
                    if previous['phase'] == 'applied':
                        if not self._current(previous) or self._ca_bytes() != verified['desired']['ca_pem'].encode('ascii'):
                            raise ValueError('Applied trust changed locally')
                        return self._public(previous)
                    if previous['attempts'] >= 3:
                        return self._public(previous, 'retry_exhausted')
                    if self.clock() < previous['retry_after']:
                        return self._public(previous, 'retry_wait')
            current = self.backend.read()
            if (binding is not None and current['binding'] != binding
                    or current['device_id'] != verified['device_id'] or current['server_name'] != verified['desired']['server_name']):
                raise ValueError('Native enrollment differs')
            before = _nodes(current['nodes'])
            if before['relay_trust_state']:
                old = model_snapshot(verified['device_id'], before)
                self._verify(old, historical=True)
                self._verify(verified, previous=old['desired'])
            ca = self._ca_bytes()
            if ca is not None and base64.b64encode(ca).decode() != before['relay_ca']:
                raise ValueError('Native trust and managed file differed')
            value = dict(version=1, phase='prepared', binding=current['binding'], snapshot=verified,
                before=before, after=after, before_ca=base64.b64encode(ca).decode() if ca is not None else None,
                attempts=previous['attempts']+1 if previous and previous_desired == verified['desired'] else 1,
                retry_after=0, receipt=None)
            self._write(value)
            prepared = True
            if value['before_ca'] != after['relay_ca'] and self.quiesce() is not True:
                raise ValueError('Owned tunnel stop was not confirmed')
            self.backend.replace(value['binding'], before, after)
            self._replace_ca(value)
            value = dict(value, phase='written')
            self._write(value)
            if self.reload() is not True or not self._current(value) or self._ca_bytes() != verified['desired']['ca_pem'].encode('ascii'):
                raise ValueError('Native trust reload was not confirmed')
            value = dict(value, phase='applied')
            self._write(value)
            return self._public(value)
        except Exception:
            if prepared:
                self.recover()
            raise TrustTransactionError('Relay trust application failed; inspect local recovery status') from None

    def confirm(self, response):
        """Persist only an exact server receipt after a verified local application."""
        try:
            value = self.read()
            if value is None or value['phase'] != 'applied' or not self._current(value):
                raise ValueError('No current applied trust')
            snapshot = self._verify(value['snapshot'])
            if self._ca_bytes() != snapshot['desired']['ca_pem'].encode('ascii'):
                raise ValueError('Applied managed file changed')
            desired = snapshot['desired']
            report = applied_request(snapshot['device_id'], desired['generation_id'], desired['generation'], desired['bundle_fingerprint'])
            receipt = applied_response(response, report)
            if value['receipt'] is not None and value['receipt']['accepted_at'] != receipt['accepted_at']:
                raise ValueError('Immutable application receipt changed')
            if value['receipt'] is not None:
                receipt = value['receipt']
            self._write(dict(value, receipt=receipt))
            return self._public(dict(value, receipt=receipt))
        except Exception:
            raise TrustTransactionError('Relay trust confirmation failed; applied trust was retained') from None
