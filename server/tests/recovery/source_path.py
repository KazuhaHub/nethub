"""Select an owned ingress source without trusting a previous access grant."""
from datetime import datetime
import ipaddress


def select_source(routes, interfaces, edge):
    network = ipaddress.IPv4Network(edge, strict=True)
    if len(routes) != 1 or routes[0].get('type', 'unicast') != 'unicast':
        raise ValueError('Recovery source route is ambiguous')
    route = routes[0]
    address = ipaddress.IPv4Address(route['prefsrc'])
    if (not address.is_private or address.is_loopback or address.is_unspecified
            or address.is_multicast or address in network):
        raise ValueError('Recovery source must be outside the container edge')
    matches = [item for item in interfaces if item.get('ifname') == route.get('dev')
               and any(value.get('family') == 'inet' and value.get('local') == str(address)
                       and value.get('scope') == 'global' for value in item.get('addr_info', []))]
    if len(matches) != 1:
        raise ValueError('Recovery source is not owned by the routed interface')
    return str(address)


def matching_grant(rows, source, actor, expiry):
    """Match the fresh HTTPS response to its exact persisted actor/source row."""
    def instant(value):
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.utcoffset() is None:
            raise ValueError('Recovery grant expiry requires a timezone')
        return parsed
    expected = instant(expiry)
    selected = [row for row in rows if row.get('source') == source and row.get('actor') == actor]
    if len(selected) != 1 or instant(selected[0]['expiry']) != expected:
        raise ValueError('Fresh Open did not grant the selected recovery source')
