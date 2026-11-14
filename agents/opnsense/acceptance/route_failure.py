"""Retain closed post-rotation diagnostics without replaying an operation."""
import json
import subprocess

from guest import GuestError
from native_model_probe import validate_route_conditions


def route_projection(route):
    return (isinstance(route, dict) and set(route) == {'curl_exit', 'http_status', 'verified'}
            and (type(route['curl_exit']) is int and 0 <= route['curl_exit'] <= 255
                 or route['curl_exit'] == 'unavailable')
            and (type(route['http_status']) is int and 100 <= route['http_status'] <= 599
                 or route['http_status'] == 'unavailable')
            and type(route['verified']) is bool)


def validate(value):
    if (not isinstance(value, dict) or set(value) != {
            'version', 'phase', 'native', 'native_probe_failure', 'routes'}
            or type(value['version']) is not int or value['version'] != 1
            or value['phase'] != 'post_rotation_route_failure'
            or value['native_probe_failure'] not in (None, 'guest_operation', 'invalid_projection')
            or not isinstance(value['routes'], dict) or not set(value['routes']) <= {'native', 'witness'}
            or any(not route_projection(route) for route in value['routes'].values())
            or (value['native'] is None) != (value['native_probe_failure'] is not None)):
        raise ValueError('Unexpected failed route evidence')
    if value['native'] is not None:
        validate_route_conditions(value['native'])


def retain(guest, evidence, observations):
    value = {'version': 1, 'phase': 'post_rotation_route_failure', 'native': None,
             'native_probe_failure': None, 'routes': {}}
    for name in ('native', 'witness'):
        route = observations.get(name)
        if route_projection(route):
            value['routes'][name] = dict(route)
    try:
        raw = guest.ssh('/usr/local/bin/python3.13 /root/nethub-ci/native_model_probe.py route\n',
                        'read-only post-rotation route conditions', timeout=12)
        if len(raw) > 4096:
            raise ValueError('Native route projection exceeds bound')
        native = json.loads(raw)
        validate_route_conditions(native)
        value['native'] = native
    except (GuestError, OSError, subprocess.TimeoutExpired):
        value['native_probe_failure'] = 'guest_operation'
    except (ValueError, TypeError, KeyError):
        value['native_probe_failure'] = 'invalid_projection'
    validate(value)
    path = evidence / 'installed-route-failure.json'
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output, indent=2)
    path.chmod(0o600)
