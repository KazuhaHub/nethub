"""Bounded public CSR messages; cache recovery still verifies the local key/signature."""
import base64
from datetime import datetime, timezone
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


def _chain_encoding(value, fingerprint):
    if not isinstance(value, str) or not 1 <= len(value) <= 32768 or not value.isascii():
        _fail()
    blocks = re.findall(r'-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n', value)
    if not 1 <= len(blocks) <= 5:
        _fail()
    canonical, seen, decoded = '', set(), []
    for index, body in enumerate(blocks):
        try:
            der = base64.b64decode(body.replace('\n', ''), validate=True)
        except ValueError:
            _fail()
        if not 128 <= len(der) <= 32768 or der in seen:
            _fail()
        seen.add(der)
        decoded.append(der)
        encoded = base64.b64encode(der).decode('ascii')
        canonical += ('-----BEGIN CERTIFICATE-----\n'
                      + ''.join(encoded[i:i + 64] + '\n' for i in range(0, len(encoded), 64))
                      + '-----END CERTIFICATE-----\n')
        if index == 0 and hashlib.sha256(der).hexdigest() != fingerprint:
            _fail()
    if canonical != value:
        _fail()
    return decoded


def delivery(value, device_id, subdomain, key_fingerprint, original, now=None):
    """Parse bound public wire material; this does not establish certificate trust.

    The caller still verifies the local CSR/key, exact SAN and full chain against
    independent native trust before staging or applying a GUI certificate.
    """
    if not isinstance(value, dict) or 'issued' not in value or len(value) > 22:
        _fail()
    settings_fields = {'agent_protocol_version', 'device_id', 'assigned_host', 'gui_key_fingerprint', 'request'}
    result = settings({key: value[key] for key in settings_fields if key in value}, device_id, subdomain, key_fingerprint)
    if (value['agent_protocol_version'].split('.')[1] == '2' or 'issued' not in value
            or result['request'] is None or not isinstance(original, dict)
            or result['request'] != original):
        _fail()
    issued = value['issued']
    result['issued'] = None
    if issued is None:
        return result
    fields = {'generation_id', 'generation', 'chain_pem', 'leaf_fingerprint',
              'not_before', 'not_after', 'valid_until', 'renew_after'}
    if (not isinstance(issued, dict) or not fields <= issued.keys() or len(issued) > len(fields) + 16
            or not isinstance(issued['generation_id'], str) or not _UUID.fullmatch(issued['generation_id'])
            or type(issued['generation']) is not int or not 1 <= issued['generation'] <= 2147483647
            or not isinstance(issued['leaf_fingerprint'], str) or not re.fullmatch('[a-f0-9]{64}', issued['leaf_fingerprint'])):
        _fail()
    _chain_encoding(issued['chain_pem'], issued['leaf_fingerprint'])
    stamps = []
    for name in ['not_before', 'not_after', 'valid_until', 'renew_after']:
        text = issued[name]
        if not isinstance(text, str) or len(text) != 27:
            _fail()
        try:
            stamp = datetime.strptime(text, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
            if stamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ') != text:
                _fail()
        except ValueError:
            _fail()
        stamps.append(stamp)
    before, after, until, renew = stamps
    now = datetime.now(timezone.utc) if now is None else now
    if not before <= now < until <= after or not before < renew < until:
        _fail()
    result['issued'] = {key: issued[key] for key in fields}
    return result


def request_issued(origin, secret, device_id, subdomain, key_fingerprint, original, context=None):
    if (not isinstance(original, dict) or not isinstance(original.get('request_id'), str)
            or not _UUID.fullmatch(original['request_id']) or not isinstance(original.get('csr_fingerprint'), str)
            or not re.fullmatch('[a-f0-9]{64}', original['csr_fingerprint'])
            or hashlib.sha256(_csr(original.get('csr_der'))).hexdigest() != original['csr_fingerprint']):
        _fail()
    body = dict(identity(device_id), request_id=original['request_id'], csr_fingerprint=original['csr_fingerprint'])
    value = request_json(origin, '/api/v1/devices/gui-certificate/issued', body, secret=secret, context=context)
    return delivery(value, device_id, subdomain, key_fingerprint, original)


def supports_application_reports(version):
    return (isinstance(version, str) and len(version) <= 64 and _SEMVER.fullmatch(version) is not None
            and version.split('.')[0] == '1' and version.split('.')[1] not in ('0', '1', '2', '3'))


def build_application_report(device_id, original, issued):
    if (not isinstance(original, dict) or not isinstance(original.get('request_id'), str)
            or not _UUID.fullmatch(original['request_id']) or not isinstance(original.get('csr_fingerprint'), str)
            or not re.fullmatch('[a-f0-9]{64}', original['csr_fingerprint'])
            or hashlib.sha256(_csr(original.get('csr_der'))).hexdigest() != original['csr_fingerprint']
            or not isinstance(issued, dict) or not isinstance(issued.get('generation_id'), str)
            or not _UUID.fullmatch(issued['generation_id']) or type(issued.get('generation')) is not int
            or not 1 <= issued['generation'] <= 2147483647 or not isinstance(issued.get('leaf_fingerprint'), str)
            or not re.fullmatch('[a-f0-9]{64}', issued['leaf_fingerprint'])):
        _fail()
    return dict(identity(device_id), request_id=original['request_id'], csr_fingerprint=original['csr_fingerprint'],
                generation_id=issued['generation_id'], generation=issued['generation'], leaf_fingerprint=issued['leaf_fingerprint'])


def application_response(value, expected):
    fields = set(expected) | {'accepted', 'accepted_at'}
    if (not isinstance(value, dict) or not fields <= value.keys() or len(value) > len(fields) + 16
            or not supports_application_reports(value['agent_protocol_version']) or value['accepted'] is not True
            or any(type(value[key]) is not type(expected[key]) or value[key] != expected[key]
                   for key in expected if key != 'agent_protocol_version')
            or not isinstance(value['accepted_at'], str) or len(value['accepted_at']) != 27):
        _fail()
    try:
        stamp = datetime.strptime(value['accepted_at'], '%Y-%m-%dT%H:%M:%S.%fZ')
        if stamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ') != value['accepted_at']:
            _fail()
    except ValueError:
        _fail()
    return {key: value[key] for key in fields}


def report_applied(origin, secret, device_id, original, issued, context=None):
    # Only the native coordinator calls this after served-certificate verification.
    body = build_application_report(device_id, original, issued)
    value = request_json(origin, '/api/v1/devices/gui-certificate/applied', body, secret=secret, context=context)
    return application_response(value, body)
