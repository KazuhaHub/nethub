"""Private bounded reconcile-failure outbox; callers hold the device mutation lock."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import uuid

MAX_EVENTS = 64
MAX_BATCH = 8
MAX_COUNT = 2**63 - 1
MAX_BYTES = 32768
FILE = 'reconcile-audit.json'


class AuditOutboxError(Exception):
    """A fixed local diagnostic without persisted input or filesystem paths."""


def canonical_id(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0
    except (ValueError, AttributeError):
        return False


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z', value):
        raise AuditOutboxError('Invalid reconcile audit state')
    try:
        datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        raise AuditOutboxError('Invalid reconcile audit state') from None
    return value


def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def object_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise AuditOutboxError('Invalid reconcile audit state')
        value[key] = item
    return value


def event(value):
    if not isinstance(value, dict) or set(value) != {'event_id', 'kind', 'count', 'first_at', 'last_at'}:
        raise AuditOutboxError('Invalid reconcile audit state')
    if (not canonical_id(value['event_id']) or uuid.UUID(value['event_id']).version != 4 or value['kind'] not in ('reconcile_failed', 'reconcile_failure_overflow')
            or type(value['count']) is not int or not 1 <= value['count'] <= MAX_COUNT
            or value['kind'] == 'reconcile_failed' and value['count'] != 1):
        raise AuditOutboxError('Invalid reconcile audit state')
    if timestamp(value['first_at']) > timestamp(value['last_at']):
        raise AuditOutboxError('Invalid reconcile audit state')
    if value['kind'] == 'reconcile_failed' and value['first_at'] != value['last_at']:
        raise AuditOutboxError('Invalid reconcile audit state')


class Outbox:
    def __init__(self, directory, device_id):
        self.directory = Path(directory)
        if not canonical_id(device_id):
            raise AuditOutboxError('Invalid reconcile audit identity')
        self.device_id = device_id

    @contextmanager
    def opened(self):
        descriptor = None
        try:
            if self.directory.absolute() != self.directory.resolve():
                raise AuditOutboxError('Unsafe reconcile audit storage')
            descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                raise AuditOutboxError('Unsafe reconcile audit storage')
            yield descriptor
        except AuditOutboxError:
            raise
        except (OSError, ValueError, TypeError, OverflowError):
            raise AuditOutboxError('Reconcile audit storage unavailable; retain local state') from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def load(self, directory):
        try:
            descriptor = os.open(FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return {'version': 1, 'device_id': self.device_id, 'events': [], 'overflow': None}
        with os.fdopen(descriptor, 'rb') as source:
            metadata = os.fstat(source.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
                    or not 0 < metadata.st_size <= MAX_BYTES):
                raise AuditOutboxError('Unsafe reconcile audit storage')
            raw = source.read(MAX_BYTES + 1)
        try:
            value = json.loads(raw, object_pairs_hook=object_pairs)
        except (ValueError, UnicodeError, RecursionError):
            raise AuditOutboxError('Invalid reconcile audit state') from None
        if (not isinstance(value, dict) or set(value) != {'version', 'device_id', 'events', 'overflow'}
                or type(value['version']) is not int or value['version'] != 1
                or value['device_id'] != self.device_id or not isinstance(value['events'], list)
                or len(value['events']) > MAX_EVENTS):
            raise AuditOutboxError('Invalid reconcile audit state')
        seen = set()
        for item in value['events']:
            event(item)
            if item['event_id'] in seen:
                raise AuditOutboxError('Invalid reconcile audit state')
            seen.add(item['event_id'])
        overflow = value['overflow']
        if overflow is not None:
            if (not isinstance(overflow, dict) or set(overflow) != {'count', 'first_at', 'last_at'}
                    or type(overflow['count']) is not int or not 1 <= overflow['count'] <= MAX_COUNT
                    or timestamp(overflow['first_at']) > timestamp(overflow['last_at'])):
                raise AuditOutboxError('Invalid reconcile audit state')
        return value

    def save(self, directory, value):
        raw = (json.dumps(value, separators=(',', ':'), sort_keys=True) + '\n').encode()
        if len(raw) > MAX_BYTES:
            raise AuditOutboxError('Reconcile audit capacity exhausted; retain local state')
        temporary = '.reconcile-audit-' + uuid.uuid4().hex
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(descriptor, 'wb') as target:
                target.write(raw)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, FILE, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass

    @staticmethod
    def promote(value):
        overflow = value['overflow']
        if overflow is not None and len(value['events']) < MAX_EVENTS:
            value['events'].append(dict(overflow, event_id=str(uuid.uuid4()), kind='reconcile_failure_overflow'))
            value['overflow'] = None

    def record_failure(self):
        with self.opened() as directory:
            value = self.load(directory)
            stamp = now()
            self.promote(value)
            if len(value['events']) < MAX_EVENTS:
                value['events'].append({'event_id': str(uuid.uuid4()), 'kind': 'reconcile_failed',
                                        'count': 1, 'first_at': stamp, 'last_at': stamp})
            elif value['overflow'] is None:
                value['overflow'] = {'count': 1, 'first_at': stamp, 'last_at': stamp}
            else:
                if value['overflow']['count'] == MAX_COUNT:
                    raise AuditOutboxError('Reconcile audit capacity exhausted; retain local state')
                value['overflow']['count'] += 1
                value['overflow']['first_at'] = min(value['overflow']['first_at'], stamp)
                value['overflow']['last_at'] = max(value['overflow']['last_at'], stamp)
            self.save(directory, value)

    def batch(self):
        with self.opened() as directory:
            value = self.load(directory)
            if value['overflow'] is not None and len(value['events']) < MAX_EVENTS:
                self.promote(value)
                self.save(directory, value)
            return value['events'][:MAX_BATCH]

    def clear_confirmed_removal(self):
        with self.opened() as directory:
            value = self.load(directory)
            if value['events'] or value['overflow'] is not None:
                raise AuditOutboxError('Retain pending reconcile audit events before removal')
            try:
                os.unlink(FILE, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.fsync(directory)

    def acknowledge(self, identifiers):
        if (not isinstance(identifiers, list) or not 1 <= len(identifiers) <= MAX_BATCH
                or any(not canonical_id(item) for item in identifiers) or len(set(identifiers)) != len(identifiers)):
            raise AuditOutboxError('Invalid reconcile audit acknowledgement')
        with self.opened() as directory:
            value = self.load(directory)
            if [item['event_id'] for item in value['events'][:len(identifiers)]] != identifiers:
                raise AuditOutboxError('Reconcile audit acknowledgement does not match retained batch')
            del value['events'][:len(identifiers)]
            self.promote(value)
            self.save(directory, value)


def supported(version):
    from enrollment import _SEMVER
    return (isinstance(version, str) and len(version) <= 64 and _SEMVER.fullmatch(version) is not None
            and version.split('.')[0] == '1' and int(version.split('.')[1]) >= 7)


def report_events(origin, secret, device_id, events):
    from enrollment import request_json
    from protocol import ProtocolError, VERSION
    if not canonical_id(device_id) or not isinstance(events, list) or not 1 <= len(events) <= MAX_BATCH:
        raise ProtocolError('Invalid reconcile audit request')
    try:
        for item in events:
            event(item)
    except AuditOutboxError:
        raise ProtocolError('Invalid reconcile audit request') from None
    identifiers = [item['event_id'] for item in events]
    if len(set(identifiers)) != len(identifiers):
        raise ProtocolError('Invalid reconcile audit request')
    reply = request_json(origin, '/api/v1/devices/reconcile-events',
                         {'agent_protocol_version': VERSION, 'device_id': device_id, 'events': events}, secret=secret)
    required = {'agent_protocol_version', 'device_id', 'accepted', 'revoked', 'event_ids'}
    if (not isinstance(reply, dict) or not required <= reply.keys() or len(reply) > len(required) + 16
            or not supported(reply['agent_protocol_version']) or reply['device_id'] != device_id
            or reply['accepted'] is not True or type(reply['revoked']) is not bool
            or reply['event_ids'] != identifiers):
        raise ProtocolError('Invalid reconcile audit acknowledgement')
    return reply['revoked']
