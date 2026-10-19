"""Validate and request enrollment; configuration remains owned by PHP."""
import base64
from datetime import datetime
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import time
from urllib.parse import urlsplit

from protocol import MAX_BODY_BYTES, ProtocolError, build_enroll_request

_HOST = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*', re.ASCII)
_UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', re.ASCII)
_SEMVER = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?', re.ASCII)
_PEM = re.compile(r'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\n', re.ASCII)


def _invalid():
    raise ProtocolError('Invalid enrollment response')


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def decode_json(body):
    if not isinstance(body, bytes) or not 0 < len(body) <= MAX_BODY_BYTES:
        _invalid()
    try:
        result = json.loads(body.decode('utf-8'), object_pairs_hook=_object,
                            parse_constant=lambda _: _invalid())
        if not isinstance(result, dict) or len(result) > 26:
            _invalid()
        pending = [(result, 0)]
        while pending:
            node, depth = pending.pop()
            if depth > 16:
                _invalid()
            if isinstance(node, dict):
                pending.extend((value, depth + 1) for value in node.values())
            elif isinstance(node, list):
                pending.extend((value, depth + 1) for value in node)
        return result
    except (ValueError, UnicodeError, RecursionError):
        _invalid()


def _secret(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value):
        _invalid()
    raw = base64.urlsafe_b64decode(value + '=')
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip('=') != value:
        _invalid()
    return value


def _hostname(value):
    return isinstance(value, str) and len(value) <= 253 and bool(_HOST.fullmatch(value))


def validate_origin(value):
    if (not isinstance(value, str) or not 8 <= len(value) <= 512
            or any(ord(c) < 33 or ord(c) > 126 for c in value) or '\\' in value):
        raise ProtocolError('Invalid console HTTPS address')
    try:
        origin = urlsplit(value)
        host = origin.hostname
        if (origin.scheme != 'https' or not host or origin.username is not None
                or origin.password is not None or origin.path not in ('', '/')
                or '?' in value or '#' in value or '%' in host
                or not 1 <= (origin.port if origin.port is not None else 443) <= 65535):
            raise ValueError()
        if not _hostname(host):
            ipaddress.ip_address(host)
        authority = '[' + host + ']' if ':' in host else host
        if origin.port is not None:
            authority += ':' + str(origin.port)
        if origin.netloc.lower() != authority:
            raise ValueError()
        return 'https://' + authority
    except ValueError:
        raise ProtocolError('Invalid console HTTPS address') from None


def validate_ca(value, now=None):
    try:
        if not isinstance(value, str) or not 64 <= len(value) <= 32768:
            _invalid()
        blocks = _PEM.findall(value)
        if not 1 <= len(blocks) <= 2 or ''.join(blocks) != value:
            _invalid()
        ders = [ssl.PEM_cert_to_DER_cert(block) for block in blocks]
        if len(set(ders)) != len(ders):
            _invalid()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=value)
        certificates = context.get_ca_certs()
        instant = time.time() if now is None else now
        if len(certificates) != len(blocks) or any(
            not ssl.cert_time_to_seconds(c['notBefore']) <= instant < ssl.cert_time_to_seconds(c['notAfter'])
            for c in certificates
        ):
            _invalid()
        return value
    except (ssl.SSLError, ValueError, KeyError):
        _invalid()


def validate_response(value, now=None):
    required = {'agent_protocol_version', 'device_id', 'device_secret', 'frp_token', 'server_addr',
                'server_port', 'server_name', 'subdomain', 'domain_claim', 'relay_ca_pem'}
    if not isinstance(value, dict) or not required <= value.keys() or len(value) > 26:
        _invalid()
    result = {name: value[name] for name in required}
    version = result['agent_protocol_version']
    if not isinstance(version, str) or len(version) > 64 or not _SEMVER.fullmatch(version):
        _invalid()
    if version.split('.', 1)[0] != '1':
        raise ProtocolError('Incompatible agent protocol; supported major is 1')
    if not isinstance(result['device_id'], str) or not _UUID.fullmatch(result['device_id']):
        _invalid()
    _secret(result['device_secret'])
    if not isinstance(result['frp_token'], str) or not re.fullmatch(r'[0-9a-f]{64}', result['frp_token']):
        _invalid()
    if not _hostname(result['server_name']):
        _invalid()
    address = result['server_addr']
    if not _hostname(address):
        try:
            if not isinstance(address, str) or '%' in address:
                _invalid()
            ipaddress.ip_address(address)
        except ValueError:
            _invalid()
    if type(result['server_port']) is not int or not 1 <= result['server_port'] <= 65535:
        _invalid()
    if not isinstance(result['subdomain'], str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', result['subdomain']):
        _invalid()
    claim = result['domain_claim']
    if not isinstance(claim, str) or not 45 <= len(claim) <= 3116 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}', claim):
        _invalid()
    payload, signature = claim.split('.')
    _secret(signature)
    try:
        raw = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
        if base64.urlsafe_b64encode(raw).decode().rstrip('=') != payload:
            _invalid()
        decoded = decode_json(raw)
        if (set(decoded) != {'device_id', 'tenant_id', 'subdomain', 'issued_at', 'key_id'}
                or decoded['device_id'] != result['device_id'] or decoded['subdomain'] != result['subdomain']
                or not isinstance(decoded['tenant_id'], str) or not _UUID.fullmatch(decoded['tenant_id'])
                or not isinstance(decoded['key_id'], str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', decoded['key_id'])
                or not isinstance(decoded['issued_at'], str)
                or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}(?:Z|[+-]\d\d:\d\d)', decoded['issued_at'])):
            _invalid()
        datetime.fromisoformat(decoded['issued_at'])
    except (ValueError, UnicodeError):
        _invalid()
    validate_ca(result['relay_ca_pem'], now)
    return result


def consume_request(path, directory=Path('/var/db/nethub-agent/requests')):
    path, directory = Path(path), Path(directory)
    descriptor = None
    try:
        info = directory.lstat()
        if (directory.resolve() != directory or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
                or path.parent != directory or not re.fullmatch(r'enroll-[a-f0-9]{32}\.json', path.name)):
            raise ValueError()
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != info.st_uid
                or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= 2048):
            raise ValueError()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError()
        path.unlink()
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = None
            request = decode_json(stream.read(2049))
        if set(request) != {'origin', 'token'}:
            raise ValueError()
        return {'origin': validate_origin(request['origin']), 'token': _secret(request['token'])}
    except (OSError, ValueError, ProtocolError):
        raise ProtocolError('Invalid private enrollment request') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def request_enrollment(origin, token, platform_version, agent_version, hostname, context=None, cluster_hint=False):
    request = build_enroll_request(token, platform_version, agent_version, hostname, cluster_hint)
    return validate_response(request_json(origin, '/api/v1/devices/enroll', request, 201, context=context))


def request_json(origin, path, request, expected_status=200, secret=None, context=None):
    origin = validate_origin(origin)
    if path not in ('/api/v1/devices/enroll', '/api/v1/devices/status', '/api/v1/devices/unenroll'):
        raise ProtocolError('Invalid device endpoint')
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Connection': 'close'}
    if secret is not None:
        headers['Authorization'] = 'Bearer ' + _secret(secret)
    endpoint = urlsplit(origin)
    connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 443, timeout=10,
                                            context=context or ssl.create_default_context())
    deadline = time.monotonic() + 20
    try:
        connection.connect()
        transport = connection.sock
        connection.request('POST', path, body=json.dumps(request).encode(), headers=headers)
        response = connection.getresponse()
        if response.status != expected_status or response.getheader('Content-Encoding', 'identity') != 'identity':
            raise ProtocolError('Console rejected the device request; check enrollment and connectivity')
        if response.getheader('Content-Type', '').split(';')[0].strip().lower() != 'application/json':
            _invalid()
        chunks = bytearray()
        while len(chunks) <= MAX_BODY_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            transport.settimeout(min(10, remaining))
            part = response.read1(min(8192, MAX_BODY_BYTES + 1 - len(chunks)))
            if not part:
                if response.length not in (None, 0):
                    _invalid()
                break
            chunks.extend(part)
            if response.isclosed():
                if response.length not in (None, 0):
                    _invalid()
                break
        return decode_json(bytes(chunks))
    except ProtocolError:
        raise
    except (OSError, http.client.HTTPException, ValueError):
        raise ProtocolError('Console HTTPS request failed; verify connectivity and certificate trust') from None
    finally:
        connection.close()
