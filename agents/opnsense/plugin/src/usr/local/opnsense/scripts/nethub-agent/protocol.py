"""Build the device enrollment request without network or appliance dependencies."""
import base64
import re

VERSION = '1.0.0'
MAX_BODY_BYTES = 65536
_HOSTNAME = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*', re.ASCII)


class ProtocolError(Exception):
    """A fixed diagnostic that contains no input or credential text."""


def build_enroll_request(token, platform_version, agent_version, hostname, cluster_hint=False):
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
    return {
        'agent_protocol_version': VERSION,
        'enroll_token': token,
        'platform': 'opnsense',
        'platform_version': platform_version,
        'agent_version': agent_version,
        'capabilities': ['remote.web'],
        'hostname': hostname,
        'cluster_hint': cluster_hint,
    }
