"""Persist one rotation candidate before network I/O; PHP owns model writes."""
import base64
from datetime import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import uuid

from certificate_key import KeyStore, CertificateKeyError
from enrollment import _secret, decode_json, validate_origin, validate_response, request_json
from protocol import ProtocolError, RotationTrustChanged, build_rotate_request


class RotationError(Exception):
    """A fixed diagnostic without journal contents or submitted credentials."""


class RotationTrustRefreshRequired(RotationError):
    """The server refused before commit and the prepared journal was removed."""


def _claim(value):
    payload = value.split('.', 1)[0]
    return decode_json(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))


def validate_rotation_response(value, previous, operation_id, candidate):
    """Require a verified HTTPS assignment to retain its original device binding."""
    if not isinstance(value, dict) or value.get('operation_id') != operation_id or len(value) > 27:
        raise RotationError('Rotation response did not confirm the saved operation')
    assignment = validate_response({key: item for key, item in value.items() if key != 'operation_id'})
    version = assignment['agent_protocol_version'].split('.')[1]
    if version in ('0', '1', '2', '3', '4', '5'):
        raise RotationError('Console does not support recoverable rotation')
    before, after = _claim(previous['domain_claim']), _claim(assignment['domain_claim'])
    if (assignment['device_id'] != previous['device_id'] or assignment['subdomain'] != previous['subdomain']
            or assignment['relay_ca_pem'] != previous['relay_ca_pem']
            or not hmac.compare_digest(assignment['device_secret'], candidate)
            or any(after[key] != before[key] for key in ['device_id', 'tenant_id', 'subdomain'])
            or datetime.fromisoformat(after['issued_at']) <= datetime.fromisoformat(before['issued_at'])):
        raise RotationError('Rotation response changed the original device binding')
    return assignment


class RotationJournal:
    """The caller holds reconcile.lock for every method and native model update.

    A prepared candidate survives all network/model failures. The active model
    may match either the original or the committed assignment; no other binding
    may adopt this journal. This store never saves native configuration itself.
    """
    FIELDS = {'version', 'phase', 'origin', 'binding', 'previous', 'operation_id', 'candidate', 'assignment', 'native_before'}

    def __init__(self, directory):
        self.directory = Path(directory)
        self.path = self.directory / 'rotation.json'
        self.files = KeyStore(self.directory)

    @staticmethod
    def binding(origin, previous):
        return hashlib.sha256(KeyStore._encoded({'origin': validate_origin(origin), 'previous': previous})).hexdigest()

    def _validate(self, value):
        if (not isinstance(value, dict) or set(value) != self.FIELDS or type(value['version']) is not int
                or value['version'] != 1 or value['phase'] not in ('prepared', 'received')
                or not isinstance(value['binding'], str) or not re.fullmatch('[a-f0-9]{64}', value['binding'])):
            raise ValueError('Invalid rotation journal')
        previous = validate_response(value['previous'])
        if previous != value['previous'] or self.binding(value['origin'], previous) != value['binding']:
            raise ValueError('Invalid original binding')
        if value['native_before'] is not None:
            from rotation_backend import assignment
            if (not isinstance(value['native_before'], dict)
                    or assignment(value['native_before']) != previous
                    or value['native_before']['console_url'] != value['origin']):
                raise ValueError('Invalid native model binding')
        build_rotate_request(previous['device_id'], value['operation_id'], value['candidate'],
                             hashlib.sha256(previous['relay_ca_pem'].encode('ascii')).hexdigest())
        if hmac.compare_digest(value['candidate'], previous['device_secret']):
            raise ValueError('Unchanged candidate')
        if value['phase'] == 'prepared':
            if value['assignment'] is not None:
                raise ValueError('Prepared journal contains an assignment')
        else:
            actual = validate_rotation_response(dict(value['assignment'], operation_id=value['operation_id']), previous,
                                                value['operation_id'], value['candidate'])
            if actual != value['assignment']:
                raise ValueError('Ambiguous assignment')
        return value

    def _directory(self):
        if self.directory.absolute() != self.directory.resolve():
            raise ValueError('Aliased rotation storage')
        self.files._protected(self.directory, directory=True)

    def _read(self):
        self._directory()
        info = self.files._protected(self.path)
        if not 1 <= info.st_size <= 131072:
            raise ValueError('Invalid rotation journal size')
        raw = self.path.read_bytes()
        value = self._validate(json.loads(raw))
        if KeyStore._encoded(value) != raw:
            raise ValueError('Ambiguous rotation journal')
        return value

    def _write(self, value):
        self._validate(value)
        self._directory()
        if self.path.exists() or self.path.is_symlink():
            self.files._protected(self.path)
        descriptor, name = tempfile.mkstemp(prefix='.rotation-', dir=self.directory)
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

    def prepare(self, origin, current, native_before=None):
        try:
            self._directory()
            origin, current = validate_origin(origin), validate_response(current)
            if self.path.exists() or self.path.is_symlink():
                value = self._read()
                if value['origin'] != origin or current not in [value['previous'], value['assignment']]:
                    raise ValueError('Current model does not match pending rotation')
                return value
            candidate = secrets.token_urlsafe(32)
            _secret(candidate)
            value = {'version': 1, 'phase': 'prepared', 'origin': origin,
                     'binding': self.binding(origin, current), 'previous': current,
                     'operation_id': str(uuid.uuid4()), 'candidate': candidate, 'assignment': None,
                     'native_before': native_before}
            self._write(value)
            return value
        except (OSError, ValueError, TypeError, KeyError, ProtocolError, CertificateKeyError):
            raise RotationError('Rotation storage or original assignment needs local review') from None

    def request(self, origin, current, context=None, transport=request_json):
        """Send the durable candidate; an ambiguous failure preserves it exactly."""
        try:
            value = self.prepare(origin, current)
            if value['phase'] == 'received':
                return value['assignment']
            body = build_rotate_request(value['previous']['device_id'], value['operation_id'], value['candidate'],
                                        hashlib.sha256(value['previous']['relay_ca_pem'].encode('ascii')).hexdigest())
            # Both attempts use the same durable operation and candidate. An
            # ambiguous original attempt may already have committed, so retry
            # with candidate authentication rather than create another secret.
            try:
                response = transport(value['origin'], '/api/v1/devices/rotate', body,
                                     secret=value['previous']['device_secret'], context=context)
            except RotationTrustChanged:
                # Only the previous-credential attempt can prove the operation
                # was refused before mutation. Candidate/transport failures stay
                # ambiguous and must never discard retained recovery state.
                if self._read() != value or value['phase'] != 'prepared':
                    raise RotationError('Rotation recovery changed; retain its journal')
                self.path.unlink()
                self.files._sync(self.directory)
                raise RotationTrustRefreshRequired('Relay trust changed; synchronize trust and retry rotation') from None
            except ProtocolError:
                response = transport(value['origin'], '/api/v1/devices/rotate', body,
                                     secret=value['candidate'], context=context)
            assignment = validate_rotation_response(response, value['previous'], value['operation_id'], value['candidate'])
            value.update(phase='received', assignment=assignment)
            self._write(value)
            return assignment
        except RotationError:
            raise
        except (OSError, ValueError, TypeError, KeyError, ProtocolError, CertificateKeyError):
            raise RotationError('Rotation response unavailable; retain the journal and retry') from None

    def complete(self, origin, saved):
        """Remove only after independent readback confirms the exact model save."""
        try:
            value = self._read()
            if (value['phase'] != 'received' or validate_origin(origin) != value['origin']
                    or validate_response(saved) != value['assignment']):
                raise ValueError('Native model save is unconfirmed')
            self.path.unlink()
            self.files._sync(self.directory)
        except (OSError, ValueError, TypeError, KeyError, ProtocolError, CertificateKeyError):
            raise RotationError('Native rotation save is unconfirmed; retain the journal') from None

    def pending_phase(self):
        """Validate retained recovery state without exposing its private fields."""
        try:
            return self._read()['phase']
        except (OSError, ValueError, TypeError, KeyError, ProtocolError, CertificateKeyError):
            raise RotationError('Pending rotation needs local review; retain its journal') from None

    def removal_candidate(self, origin, device_id, current_secret):
        """Recover removal authentication after an unknown rotation commit."""
        try:
            value = self._read()
            if (validate_origin(origin) != value['origin'] or device_id != value['previous']['device_id']
                    or current_secret not in (value['previous']['device_secret'], value['candidate'])):
                raise ValueError('Removal differs from pending rotation')
            return value['candidate']
        except (OSError, ValueError, TypeError, KeyError, ProtocolError, CertificateKeyError):
            raise RotationError('Pending rotation identity differs from removal; retain its journal') from None

    def forget_revoked(self, confirmed_device_id):
        """Caller independently confirmed server revocation and cleared the model."""
        try:
            value = self._read()
            if value['previous']['device_id'] != confirmed_device_id:
                raise ValueError('Removal confirmation differs from rotation')
            self.path.unlink()
            self.files._sync(self.directory)
        except (OSError, ValueError, TypeError, KeyError, ProtocolError, CertificateKeyError):
            raise RotationError('Pending rotation removal is unconfirmed; retain its journal') from None
