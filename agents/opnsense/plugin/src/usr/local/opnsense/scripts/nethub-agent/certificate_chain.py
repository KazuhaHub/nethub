"""Verify public GUI material with the existing device key and native trust."""
import base64
import calendar
from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from certificate_key import CertificateKeyError
from certificate_protocol import _chain_encoding, delivery
from certificate_request import CertificateRequestError, RequestStore, _der, _take
from protocol import ProtocolError


class CertificateChainError(Exception):
    """A fixed diagnostic without certificates, keys or child-process output."""


def _time(data):
    tag = data[0] if data else 0
    if tag not in (0x17, 0x18):
        raise ValueError('Invalid certificate time')
    text, tail = _take(data, tag)
    text = text.decode('ascii')
    if tag == 0x17:
        if len(text) != 13:
            raise ValueError('Invalid UTC time')
        year = int(text[:2])
        text = str(year + (2000 if year < 50 else 1900)) + text[2:]
    if len(text) != 15 or text[-1] != 'Z' or not text[:-1].isdigit():
        raise ValueError('Invalid certificate time')
    value = datetime.strptime(text, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
    return value, tail


def _common_name(subject):
    found = []
    while subject:
        names, subject = _take(subject, 0x31)
        while names:
            entry, names = _take(names, 0x30)
            oid, value = _take(entry, 6)
            if not value:
                raise ValueError('Missing subject value')
            tag = value[0]
            text, tail = _take(value, tag)
            if tail:
                raise ValueError('Invalid subject value')
            if oid == bytes.fromhex('550403'):
                encoding = {0x0c: 'utf-8', 0x13: 'ascii', 0x16: 'ascii', 0x1e: 'utf-16-be', 0x1c: 'utf-32-be'}.get(tag)
                if encoding is None:
                    raise ValueError('Unsupported common name')
                found.append(text.decode(encoding))
    if len(found) > 1:
        raise ValueError('Repeated common name')
    return found[0] if found else ''


def _certificate(der):
    body, tail = _take(der, 0x30)
    if tail:
        raise ValueError('Trailing certificate data')
    tbs, body = _take(body, 0x30)
    _, body = _take(body, 0x30)
    signature, body = _take(body, 3)
    if body or not signature or signature[0] != 0:
        raise ValueError('Invalid certificate signature')
    version = b''
    if tbs and tbs[0] == 0xa0:
        version, tbs = _take(tbs, 0xa0)
    _, tbs = _take(tbs, 2)
    _, tbs = _take(tbs, 0x30)
    issuer, tbs = _take(tbs, 0x30)
    validity, tbs = _take(tbs, 0x30)
    before, validity = _time(validity)
    after, validity = _time(validity)
    if validity:
        raise ValueError('Trailing certificate validity')
    subject, tbs = _take(tbs, 0x30)
    public, tbs = _take(tbs, 0x30)
    for tag in [0x81, 0x82]:
        if tbs and tbs[0] == tag:
            _, tbs = _take(tbs, tag)
    extensions = {}
    if tbs:
        wrapper, tail = _take(tbs, 0xa3)
        sequence, extra = _take(wrapper, 0x30)
        if tail or extra:
            raise ValueError('Trailing certificate extensions')
        while sequence:
            entry, sequence = _take(sequence, 0x30)
            oid, entry = _take(entry, 6)
            if entry and entry[0] == 1:
                critical, entry = _take(entry, 1)
                if critical != b'\xff':
                    raise ValueError('Noncanonical critical flag')
            value, entry = _take(entry, 4)
            if entry or oid in extensions or len(extensions) >= 64:
                raise ValueError('Invalid certificate extension')
            extensions[oid] = value
    return {'version': version, 'before': before, 'after': after, 'issuer': issuer, 'subject': subject, 'cn': _common_name(subject),
            'public': base64.urlsafe_b64encode(_der(0x30, public)).decode('ascii').rstrip('='), 'extensions': extensions}


def _leaf_profile(value, host, public):
    extensions = value['extensions']
    if (value['version'] != bytes.fromhex('020102') or value['public'] != public
            or value['cn'] not in ('', host)
            or extensions.get(bytes.fromhex('551d13')) != bytes.fromhex('3000')
            or extensions.get(bytes.fromhex('551d11')) != _der(0x30, _der(0x82, host.encode('ascii')))):
        raise ValueError('Certificate does not match the enrolled profile')
    bits, tail = _take(extensions[bytes.fromhex('551d0f')], 3)
    if tail or not 2 <= len(bits) <= 3 or bits[0] > 7 or not bits[1] & 0x80:
        raise ValueError('Certificate cannot sign TLS handshakes')
    usages, tail = _take(extensions[bytes.fromhex('551d25')], 0x30)
    allowed = False
    while usages:
        oid, usages = _take(usages, 6)
        allowed = allowed or oid == bytes.fromhex('2b06010505070301')
    if tail or not allowed:
        raise ValueError('Certificate is not for TLS servers')


class ChainVerifier:
    """The caller holds reconcile.lock; verification never applies a certificate.

    An optional CA file is independently provisioned by the local operator. The
    default uses native OpenSSL system trust. Response certificates are always
    untrusted input and can never supply their own trusted root.
    """

    def __init__(self, key_store, trusted_ca_file=None):
        self.key_store = key_store
        self.trusted_ca_file = Path(trusted_ca_file) if trusted_ca_file is not None else None

    def _verify(self, arguments, expected):
        env = {key: value for key, value in os.environ.items()
               if key not in ('SSL_CERT_FILE', 'SSL_CERT_DIR', 'OPENSSL_CONF', 'OPENSSL_CONF_INCLUDE', 'OPENSSL_MODULES')}
        env.update(LANG='C', LC_ALL='C')
        result = subprocess.run([self.key_store.openssl, *map(str, arguments)], capture_output=True, timeout=5, env=env)
        if result.returncode or len(result.stdout) > 4096 or len(result.stderr) > 8192 or result.stdout.strip() != expected:
            raise ValueError('Native independent chain verification failed')

    def _roots(self):
        if not self.trusted_ca_file.is_absolute():
            raise ValueError('Independent CA path must be absolute')
        path = self.trusted_ca_file.resolve(strict=True)
        for parent in [self.trusted_ca_file.parent, path.parent]:
            info = parent.lstat()
            if (not stat.S_ISDIR(info.st_mode)
                    or hasattr(os, 'geteuid') and (info.st_uid != os.geteuid() or info.st_mode & 0o022)):
                raise ValueError('Independent CA parent is not protected')
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= 2097152
                or hasattr(os, 'geteuid') and (before.st_uid != os.geteuid() or before.st_mode & 0o022)):
            raise ValueError('Independent CA file is not protected')
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError('Independent CA file changed')
            value = stream.read(2097153)
        if len(value) > 2097152 or b'PRIVATE KEY' in value or b'-----BEGIN CERTIFICATE-----' not in value:
            raise ValueError('Independent public roots unavailable')
        return value

    def verify(self, message, device_id, subdomain, original):
        try:
            key = self.key_store._load()
            parsed = delivery(message, device_id, subdomain, key['fingerprint'], original)
            host = parsed['assigned_host']
            requests = RequestStore(self.key_store.directory.parent / 'gui-request', self.key_store)
            requests._validate({'version': 1, 'host': host, 'key_fingerprint': key['fingerprint'], 'csr': original['csr_der']}, host, key)
            if parsed['issued'] is None:
                return parsed
            issued = parsed['issued']
            certificates = _chain_encoding(issued['chain_pem'], issued['leaf_fingerprint'])
            information = [_certificate(der) for der in certificates]
            _leaf_profile(information[0], host, key['public_key'])
            if (len(set(certificates)) != len(certificates)
                    or any(child['issuer'] != parent['subject'] for child, parent in zip(information, information[1:]))):
                raise ValueError('Certificate chain order differs from the signed issuers')
            now = datetime.now(timezone.utc)
            for cert in information:
                if not cert['before'] <= now < cert['after']:
                    raise ValueError('Certificate validity mismatch')
            layout = '%Y-%m-%dT%H:%M:%S.%fZ'
            if (issued['not_before'] != information[0]['before'].strftime(layout)
                    or issued['not_after'] != information[0]['after'].strftime(layout)
                    or datetime.strptime(issued['valid_until'], layout).replace(tzinfo=timezone.utc) > min(cert['after'] for cert in information)):
                raise ValueError('Certificate metadata differs from signed material')
            self.key_store._protected(self.key_store.directory.parent, directory=True)
            with tempfile.TemporaryDirectory(prefix='.gui-chain-', dir=self.key_store.directory.parent) as temporary:
                temporary = Path(temporary)
                self.key_store._protected(temporary, directory=True)

                def write(name, content):
                    path = temporary / name
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, 'wb') as stream:
                        stream.write(content)
                    return path

                def pem(der):
                    encoded = base64.b64encode(der)
                    return b'-----BEGIN CERTIFICATE-----\n' + b''.join(encoded[i:i+64] + b'\n' for i in range(0, len(encoded), 64)) + b'-----END CERTIFICATE-----\n'

                leaf = write('leaf.pem', pem(certificates[0]))
                arguments = ['verify', '-purpose', 'sslserver', '-verify_hostname', host]
                if self.trusted_ca_file is not None:
                    roots = write('independent-roots.pem', self._roots())
                    arguments.extend(['-no-CApath', '-no-CAstore', '-CAfile', roots])
                if len(certificates) > 1:
                    arguments.extend(['-untrusted', write('untrusted.pem', b''.join(pem(der) for der in certificates[1:]))])
                arguments.append(leaf)
                expected = str(leaf).encode('utf-8') + b': OK'
                self._verify(arguments, expected)
                # Check the independently selected trust path through the
                # claimed effective lifetime, including a root omitted from the
                # response. X.509 validity is exclusive at its final second.
                until = datetime.strptime(issued['valid_until'], layout).replace(tzinfo=timezone.utc)
                endpoint = calendar.timegm(until.utctimetuple()) - (1 if until.microsecond == 0 else 0)
                self._verify(arguments[:-1] + ['-attime', str(endpoint), leaf], expected)
            return parsed
        except (CertificateKeyError, CertificateRequestError, ProtocolError, OSError, ValueError, KeyError, TypeError, IndexError, UnicodeError, subprocess.SubprocessError):
            raise CertificateChainError('GUI certificate verification failed; enrolled key and configuration were retained') from None
