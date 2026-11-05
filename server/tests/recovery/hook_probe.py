"""Count only fixed connection-hook decisions from private bounded service logs."""
import json
import ipaddress
import re


DECISIONS = ('allowed', 'device_denied', 'unavailable', 'busy', 'invalid_request',
             'invalid_claim', 'proxy_policy', 'connection_policy')


def bounded_lines(raw):
    if not isinstance(raw, bytes) or len(raw) > 256 * 1024 or len(raw.splitlines()) > 1024:
        raise ValueError('Restored connection-hook observation unavailable')
    return raw.splitlines()


def project_rejected_sources(raw, expected):
    """Compare private frps rejection peers with Open; never export either IP."""
    message = 'Restored rejected-source observation unavailable'
    try:
        if not isinstance(expected, str) or not 1 <= len(expected) <= 45:
            raise ValueError
        expected = ipaddress.ip_address(expected)
        if isinstance(expected, ipaddress.IPv6Address) and expected.ipv4_mapped:
            expected = expected.ipv4_mapped
        if expected.is_unspecified or expected.is_multicast or getattr(expected, 'scope_id', None):
            raise ValueError
        counts = dict.fromkeys(('rejected_entries', 'source_matches_open', 'source_differs_from_open',
                                'loopback', 'private', 'other'), 0)
        prefix, suffix = b'the user conn [', b'] was rejected, err:'
        for line in bounded_lines(raw):
            # Authz emits JSON with fixed fields; only the pinned frps text
            # rejection format is an observation of its actual connection peer.
            if line.lstrip().startswith(b'{') or prefix not in line:
                continue
            if line.count(prefix) != 1 or line.count(suffix) != 1:
                raise ValueError
            address = line.partition(prefix)[2].partition(suffix)[0].decode('ascii')
            if re.fullmatch(r'(?:[0-9.]+|\[[0-9a-fA-F:.]+\]):[0-9]{1,5}', address) is None:
                raise ValueError
            host, _, port = address.rpartition(':')
            if not 0 < int(port) <= 65535:
                raise ValueError
            peer = ipaddress.ip_address(host.strip('[]'))
            if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped:
                peer = peer.ipv4_mapped
            if peer.is_unspecified or peer.is_multicast:
                raise ValueError
            counts['rejected_entries'] += 1
            counts['source_matches_open' if peer == expected else 'source_differs_from_open'] += 1
            counts['loopback' if peer.is_loopback else 'private' if peer.is_private else 'other'] += 1
        return {'version': 1, 'available': counts['rejected_entries'] > 0, **counts}
    except (ValueError, TypeError, UnicodeError):
        raise ValueError(message) from None


def project(raw):
    message = 'Restored connection-hook observation unavailable'
    lines = bounded_lines(raw)
    counts = dict.fromkeys(DECISIONS, 0)
    causes = dict.fromkeys(('device_state', 'source_access', 'unavailable'), 0)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(message)
            value[key] = item
        return value
    for line in lines:
        try:
            value = json.loads(line, object_pairs_hook=unique)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        except RecursionError:
            raise ValueError(message) from None
        if not isinstance(value, dict) or value.get('msg') != 'Relay hook decision' or value.get('operation') != 'NewUserConn':
            continue
        decision = value.get('decision')
        if not isinstance(decision, str) or decision not in counts:
            raise ValueError(message)
        counts[decision] += 1
        if decision == 'device_denied':
            cause = value.get('cause', 'unavailable')
            if not isinstance(cause, str) or cause not in causes:
                raise ValueError(message)
            causes[cause] += 1
    return {'version': 2, 'connection_decisions': counts, 'denial_causes': causes}
