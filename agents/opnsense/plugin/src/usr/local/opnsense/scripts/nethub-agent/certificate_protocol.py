"""Bounded public CSR messages; cache recovery still verifies the local key/signature."""
import base64
from datetime import datetime
import hashlib
import re

from enrollment import _SEMVER, _UUID, request_json
from lifecycle import identity
from protocol import ProtocolError


def _fail():
    raise ProtocolError('Invalid certificate acknowledgement')


def _csr(value):
    if not isinstance(value, str) or not 4 <= len(value) <= 5464:
        _fail()
    try:
        der = base64.b64decode(value, validate=True)
    except ValueError:
        _fail()
    if not 1 <= len(der) <= 4096 or base64.b64encode(der).decode('ascii') != value:
        _fail()
    return der


def build_request(device_id, csr_der):
    _csr(csr_der)
    return dict(identity(device_id), csr_der=csr_der)


def settings(value, device_id, subdomain, key_fingerprint):
    fields = {'agent_protocol_version', 'device_id', 'assigned_host', 'gui_key_fingerprint', 'request'}
    if (not isinstance(value, dict) or not fields <= value.keys() or len(value) > len(fields) + 16
            or not isinstance(value['agent_protocol_version'], str)
            or len(value['agent_protocol_version']) > 64 or not _SEMVER.fullmatch(value['agent_protocol_version'])
            or value['agent_protocol_version'].split('.')[0] != '1'
            or value['agent_protocol_version'].split('.')[1] in ('0', '1')
            or value['device_id'] != device_id or not isinstance(device_id, str) or not _UUID.fullmatch(device_id)
            or not isinstance(subdomain, str) or not re.fullmatch('[a-z0-9]{8}', subdomain)
            or not isinstance(key_fingerprint, str) or not re.fullmatch('[a-f0-9]{64}', key_fingerprint)
            or value['gui_key_fingerprint'] != key_fingerprint
            or not isinstance(value['assigned_host'], str) or len(value['assigned_host']) > 253
            or not re.fullmatch(r'[a-z0-9]{8}(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', value['assigned_host'])
            or value['assigned_host'].split('.')[0] != subdomain):
        _fail()
    result = {key: value[key] for key in fields}
    record = value['request']
    if record is None:
        return result
    required = {'request_id', 'csr_der', 'csr_fingerprint', 'created_at'}
    if (not isinstance(record, dict) or not required <= record.keys() or len(record) > len(required) + 16
            or not isinstance(record['request_id'], str) or not _UUID.fullmatch(record['request_id'])
            or not isinstance(record['csr_fingerprint'], str) or not re.fullmatch('[a-f0-9]{64}', record['csr_fingerprint'])
            or not isinstance(record['created_at'], str) or len(record['created_at']) != 27):
        _fail()
    try:
        stamp = datetime.strptime(record['created_at'], '%Y-%m-%dT%H:%M:%S.%fZ')
        if stamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ') != record['created_at']:
            _fail()
    except ValueError:
        _fail()
    if hashlib.sha256(_csr(record['csr_der'])).hexdigest() != record['csr_fingerprint']:
        _fail()
    result['request'] = {key: record[key] for key in required}
    return result


def request_settings(origin, secret, device_id, subdomain, key_fingerprint, context=None):
    value = request_json(origin, '/api/v1/devices/gui-certificate/settings', identity(device_id), secret=secret, context=context)
    return settings(value, device_id, subdomain, key_fingerprint)


def submit_request(origin, secret, device_id, subdomain, key_fingerprint, csr_der, context=None):
    body = build_request(device_id, csr_der)
    value = request_json(origin, '/api/v1/devices/gui-certificate/request', body, secret=secret, context=context)
    result = settings(value, device_id, subdomain, key_fingerprint)
    if result['request'] is None or result['request']['csr_der'] != csr_der:
        _fail()
    return result
