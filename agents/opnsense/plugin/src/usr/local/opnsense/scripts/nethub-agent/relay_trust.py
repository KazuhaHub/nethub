"""Verify desired public trust; this module never installs or reports it."""
import base64
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from certificate_chain import _certificate
from certificate_request import _take
from enrollment import _hostname
from protocol import ProtocolError
from relay_trust_protocol import _invalid, _response, _stamp, applied_request


_FIELDS = {'generation_id', 'generation', 'server_name', 'ca_pem', 'bundle_fingerprint', 'published_at', 'not_before', 'valid_until'}
_PEM = re.compile(r'-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n', re.ASCII)
_SIGNATURES = {bytes.fromhex(value) for value in (
    '2a864886f70d01010b', '2a864886f70d01010c', '2a864886f70d01010d',
    '2a8648ce3d040302', '2a8648ce3d040303', '2a8648ce3d040304', '2b6570')}


def _hash_algorithm(encoded):
    algorithm, tail = _take(encoded, 0x30)
    oid, parameters = _take(algorithm, 6)
    lengths = {bytes.fromhex('608648016503040201'): 32, bytes.fromhex('608648016503040202'): 48,
               bytes.fromhex('608648016503040203'): 64}
    if tail or parameters not in (b'', b'\x05\x00') or oid not in lengths:
        _invalid()
    return oid, lengths[oid]


def _signature(algorithm):
    oid, parameters = _take(algorithm, 6)
    if oid in _SIGNATURES:
        return
    if oid != bytes.fromhex('2a864886f70d01010a'):
        _invalid()
    # PSS's omitted parameters default to SHA-1; its OID alone is insufficient.
    sequence, tail = _take(parameters, 0x30)
    hash_algorithm, sequence = _take(sequence, 0xa0)
    digest, length = _hash_algorithm(hash_algorithm)
    mask, sequence = _take(sequence, 0xa1)
    mask, extra = _take(mask, 0x30)
    mask_oid, mask_hash = _take(mask, 6)
    if tail or extra or mask_oid != bytes.fromhex('2a864886f70d010108') or _hash_algorithm(mask_hash)[0] != digest:
        _invalid()
    salt, sequence = _take(sequence, 0xa2)
    salt, extra = _take(salt, 2)
    if extra or salt != bytes([length]):
        _invalid()
    if sequence:
        trailer, sequence = _take(sequence, 0xa3)
        if trailer != b'\x02\x01\x01' or sequence:
            _invalid()


def _root(der):
    value = _certificate(der)
    if value['issuer'] != value['subject']:
        _invalid()
    body, _ = _take(der, 0x30)
    _, body = _take(body, 0x30)
    algorithm, _ = _take(body, 0x30)
    _signature(algorithm)
    constraints, tail = _take(value['extensions'][bytes.fromhex('551d13')], 0x30)
    ca, constraints = _take(constraints, 1)
    if ca != b'\xff' or tail:
        _invalid()
    if constraints:
        length, constraints = _take(constraints, 2)
        if not length or length[0] & 128:
            _invalid()
    if constraints:
        _invalid()
    usage = value['extensions'].get(bytes.fromhex('551d0f'))
    if usage is not None:
        bits, tail = _take(usage, 3)
        if tail or not 2 <= len(bits) <= 3 or bits[0] > 7 or not bits[1] & 4:
            _invalid()
    return value


def verify_settings(value, device_id, server_name, directory, previous=None, now=None, openssl='/usr/bin/openssl'):
    """Return a detached verified snapshot, with no mutation of durable state.

    The caller supplies the enrolled relay identity and its last verified desired
    snapshot under reconcile.lock. Console HTTPS authentication remains mandatory.
    Self-signature verification establishes root integrity, not server authority.
    """
    try:
        result = _response(value, device_id, {'agent_protocol_version', 'device_id', 'desired'})
        if not _hostname(server_name) or server_name != server_name.lower():
            _invalid()
        desired = result['desired']
        if desired is None:
            if previous is not None:
                _invalid()
            return result
        if not isinstance(desired, dict) or not _FIELDS <= desired.keys() or len(desired) > len(_FIELDS) + 16:
            _invalid()
        desired = {key: desired[key] for key in _FIELDS}
        applied_request(device_id, desired['generation_id'], desired['generation'], desired['bundle_fingerprint'])
        if desired['server_name'] != server_name:
            _invalid()
        before, until, published = (_stamp(desired[key]) for key in ('not_before', 'valid_until', 'published_at'))
        instant = datetime.now(timezone.utc) if now is None else now
        if not isinstance(instant, datetime) or instant.tzinfo is None or not before <= instant < until or not before <= published < until:
            _invalid()
        if previous is not None:
            applied_request(device_id, previous['generation_id'], previous['generation'], previous['bundle_fingerprint'])
            if (desired['generation'] < previous['generation']
                    or desired['generation'] == previous['generation'] and desired != {key: previous[key] for key in _FIELDS}
                    or desired['generation'] > previous['generation'] and desired['generation_id'] == previous['generation_id']):
                _invalid()
        pem = desired['ca_pem']
        if not isinstance(pem, str) or not 64 <= len(pem) <= 32768 or not pem.isascii():
            _invalid()
        blocks = _PEM.findall(pem)
        if not 1 <= len(blocks) <= 2:
            _invalid()
        roots, canonical, windows = [], '', []
        for block in blocks:
            der = base64.b64decode(block.replace('\n', ''), validate=True)
            root = _root(der)
            roots.append(hashlib.sha256(der).hexdigest())
            windows.append((root['before'], root['after']))
            encoded = base64.b64encode(der).decode('ascii')
            canonical += '-----BEGIN CERTIFICATE-----\n' + ''.join(encoded[i:i+64]+'\n' for i in range(0, len(encoded), 64)) + '-----END CERTIFICATE-----\n'
        if (canonical != pem or roots != sorted(set(roots))
                or max(window[0] for window in windows) != before or min(window[1] for window in windows) != until
                or hashlib.sha256(('nethub-relay-trust-v1:'+pem).encode('ascii')).hexdigest() != desired['bundle_fingerprint']):
            _invalid()
        parent = Path(directory)
        info = parent.lstat()
        if (not parent.is_absolute() or not stat.S_ISDIR(info.st_mode) or parent.resolve() != parent
                or hasattr(os, 'geteuid') and (info.st_uid != os.geteuid() or info.st_mode & 0o077)):
            _invalid()
        env = {key: val for key, val in os.environ.items() if key not in
               ('SSL_CERT_FILE', 'SSL_CERT_DIR', 'OPENSSL_CONF', 'OPENSSL_CONF_INCLUDE', 'OPENSSL_MODULES')}
        env.update(LANG='C', LC_ALL='C')
        with tempfile.TemporaryDirectory(prefix='relay-trust-', dir=parent) as temporary:
            for index, block in enumerate(_PEM.finditer(pem)):
                path = Path(temporary)/('root-'+str(index)+'.pem')
                with path.open('x', encoding='ascii', newline='\n') as output:
                    os.chmod(path, 0o600)
                    output.write(block.group())
                checked = subprocess.run([openssl, 'verify', '-check_ss_sig', '-no-CAfile', '-no-CApath', '-no-CAstore',
                    '-attime', str(int(instant.timestamp())), '-trusted', str(path), str(path)],
                    env=env, capture_output=True, timeout=5)
                if checked.returncode or checked.stdout.strip() != (str(path)+': OK').encode() or len(checked.stderr) > 8192:
                    _invalid()
        result['desired'] = desired
        return result
    except (ValueError, KeyError, TypeError, OverflowError, OSError, subprocess.SubprocessError):
        raise ProtocolError('Invalid relay trust response') from None
