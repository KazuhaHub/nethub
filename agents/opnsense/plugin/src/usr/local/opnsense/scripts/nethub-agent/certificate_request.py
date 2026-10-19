"""Persist one signed request for an already bound device key and DNS assignment."""
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from certificate_key import CertificateKeyError


class CertificateRequestError(Exception):
    """A fixed diagnostic without request, key or child-process output."""


def _der(tag, content):
    length = len(content)
    if length < 128:
        encoded = bytes([length])
    elif length < 256:
        encoded = bytes([0x81, length])
    else:
        encoded = bytes([0x82]) + length.to_bytes(2, 'big')
    return bytes([tag]) + encoded + content


def _take(data, tag):
    if len(data) < 2 or data[0] != tag:
        raise ValueError('Unexpected DER field')
    length, offset = data[1], 2
    if length >= 128:
        count = length & 127
        if count not in (1, 2) or len(data) < 2 + count or data[2] == 0:
            raise ValueError('Invalid DER length')
        length = int.from_bytes(data[2:2 + count], 'big')
        offset += count
        if length < 128 or (count == 2 and length < 256):
            raise ValueError('Noncanonical DER length')
    if len(data) < offset + length:
        raise ValueError('Truncated DER field')
    return data[offset:offset + length], data[offset + length:]


class RequestStore:
    """The caller holds reconcile.lock and authorizes the live assignment.

    This component does not create a key, change an existing request, contact an
    issuer or select a GUI certificate. Missing persisted requests after an
    accepted submission must be recovered by the future job protocol, not by
    treating this initializer as a polling endpoint.
    """

    def __init__(self, directory, key_store):
        self.directory = Path(directory)
        self.key_store = key_store

    def _command(self, arguments, content):
        result = subprocess.run([self.key_store.openssl, *arguments], input=content,
                                capture_output=True, timeout=3)
        if result.returncode or len(result.stdout) > 8192:
            raise CertificateRequestError('Could not validate the device certificate request')
        return result.stdout

    @staticmethod
    def _identity(host, fingerprint):
        if (not isinstance(host, str) or len(host) > 253
                or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', host)
                or not isinstance(fingerprint, str) or not re.fullmatch('[a-f0-9]{64}', fingerprint)):
            raise ValueError('Invalid assignment')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return
        raise ValueError('IP assignment is not supported')

    @staticmethod
    def _information(host, public):
        # Fixed PKCS#10 profile: version zero, empty subject, bound SPKI and one
        # noncritical SAN extension containing only the assigned DNS identity.
        san = _der(0x30, _der(0x82, host.encode('ascii')))
        extension = _der(0x30, bytes.fromhex('0603551d11') + _der(4, san))
        attribute = _der(0x30, bytes.fromhex('06092a864886f70d01090e') + _der(0x31, _der(0x30, extension)))
        spki = base64.urlsafe_b64decode(public + '==')
        return _der(0x30, bytes.fromhex('0201003000') + spki + _der(0xa0, attribute))

    @staticmethod
    def _encoded(value):
        return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')

    def _validate(self, value, host, key):
        if (not isinstance(value, dict) or set(value) != {'version', 'host', 'key_fingerprint', 'csr'}
                or type(value['version']) is not int or value['version'] != 1 or value['host'] != host
                or value['key_fingerprint'] != key['fingerprint'] or not isinstance(value['csr'], str)):
            raise ValueError('Request assignment changed')
        der = base64.b64decode(value['csr'], validate=True)
        if len(der) > 4096 or base64.b64encode(der).decode('ascii') != value['csr']:
            raise ValueError('Invalid request encoding')
        body, tail = _take(der, 0x30)
        information = self._information(host, key['public_key'])
        algorithm = bytes.fromhex('300a06082a8648ce3d040302')
        if tail or not body.startswith(information + algorithm):
            raise ValueError('Request profile changed')
        signature, tail = _take(body[len(information + algorithm):], 3)
        if tail or not 9 <= len(signature) <= 73 or signature[0] != 0:
            raise ValueError('Invalid request signature')
        self._command(['req', '-inform', 'DER', '-verify', '-noout'], der)
        encoded = base64.b64encode(der)
        return (b'-----BEGIN CERTIFICATE REQUEST-----\n'
                + b''.join(encoded[i:i + 64] + b'\n' for i in range(0, len(encoded), 64))
                + b'-----END CERTIFICATE REQUEST-----\n')

    def ensure(self, host, expected_fingerprint):
        """Initialize once, or return the exact intact cached signed request."""
        temporary = None
        try:
            self._identity(host, expected_fingerprint)
            if (self.directory.absolute() != self.directory.resolve()
                    or self.key_store.directory.absolute() != self.key_store.directory.resolve()
                    or self.directory == self.key_store.directory):
                raise ValueError('Unsafe request path')
            self.key_store._protected(self.directory.parent, directory=True)
            key = self.key_store._load()
            if key['fingerprint'] != expected_fingerprint:
                raise ValueError('Bound key changed')
            if self.directory.exists() or self.directory.is_symlink():
                self.key_store._protected(self.directory, directory=True)
                if {p.name for p in self.directory.iterdir()} != {'request.json'}:
                    raise ValueError('Unknown request storage')
                path = self.directory / 'request.json'
                info = self.key_store._protected(path)
                if not 128 <= info.st_size <= 8192:
                    raise ValueError('Invalid request record size')
                raw = path.read_bytes()
                value = json.loads(raw)
                if self._encoded(value) != raw:
                    raise ValueError('Ambiguous request record')
                return self._validate(value, host, key)
            temporary = Path(tempfile.mkdtemp(prefix='.gui-csr-', dir=self.directory.parent))
            information = self._information(host, key['public_key'])
            signature = self._command(['dgst', '-sha256', '-sign', str(self.key_store.directory / 'key.pem'),
                                       '-passin', 'pass:'], information)
            der = _der(0x30, information + bytes.fromhex('300a06082a8648ce3d040302') + _der(3, b'\0' + signature))
            value = {'version': 1, 'host': host, 'key_fingerprint': expected_fingerprint,
                     'csr': base64.b64encode(der).decode('ascii')}
            pem = self._validate(value, host, key)
            descriptor = os.open(temporary / 'request.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(self._encoded(value))
                output.flush()
                os.fsync(output.fileno())
            self.key_store._sync(temporary)
            temporary.rename(self.directory)
            temporary = None
            self.key_store._sync(self.directory.parent)
            return pem
        except (CertificateKeyError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            raise CertificateRequestError('Device certificate request needs local review') from None
        finally:
            if temporary is not None:
                try:
                    path = temporary / 'request.json'
                    if path.exists():
                        path.unlink()
                    temporary.rmdir()
                except OSError:
                    raise CertificateRequestError('Device certificate request needs local review') from None
