"""Build the device enrollment request without network or appliance dependencies."""
import base64
import hashlib
import re

VERSION = '1.5.0'
MAX_BODY_BYTES = 65536
_HOSTNAME = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*', re.ASCII)


class ProtocolError(Exception):
    """A fixed diagnostic that contains no input or credential text."""


def gui_key_fingerprint(value):
    """Validate canonical public P-256 SPKI without loading private key material."""
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{121}[AQgw]', value):
        raise ProtocolError('Invalid certificate public key')
    raw = base64.urlsafe_b64decode(value + '==')
    prefix = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004')
    if len(raw) != 91 or not raw.startswith(prefix) or base64.urlsafe_b64encode(raw).decode().rstrip('=') != value:
        raise ProtocolError('Invalid certificate public key')
    # Public point validation uses the P-256 parameters in NIST SP 800-186.
    prime = (1 << 256) - (1 << 224) + (1 << 192) + (1 << 96) - 1
    coefficient = int('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b', 16)
    x, y = int.from_bytes(raw[27:59]), int.from_bytes(raw[59:91])
    if x >= prime or y >= prime or (y*y - x*x*x + 3*x - coefficient) % prime != 0:
        raise ProtocolError('Invalid certificate public key')
    return hashlib.sha256(raw).hexdigest()


def build_enroll_request(token, platform_version, agent_version, hostname, cluster_hint=False, gui_public_key=None):
    if (not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token)
            or type(cluster_hint) is not bool or not isinstance(hostname, str)
            or len(hostname) > 253 or not _HOSTNAME.fullmatch(hostname)):
        raise ProtocolError('Invalid enrollment input')
    decoded = base64.urlsafe_b64decode(token + '=')
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip('=') != token:
        raise ProtocolError('Invalid enrollment input')
    for value in (platform_version, agent_version):
        if (not isinstance(value, str) or len(value) > 128
                or any(ord(c) < 32 or ord(c) > 126 for c in value)):
            raise ProtocolError('Invalid enrollment input')
    result = {
        'agent_protocol_version': VERSION,
        'enroll_token': token,
        'platform': 'opnsense',
        'platform_version': platform_version,
        'agent_version': agent_version,
        'capabilities': ['remote.web'],
        'hostname': hostname,
        'cluster_hint': cluster_hint,
    }
    if gui_public_key is not None:
        gui_key_fingerprint(gui_public_key)
        result['gui_public_key'] = gui_public_key
    return result
