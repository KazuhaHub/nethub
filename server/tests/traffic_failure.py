"""Publish only a closed browser failure projection; raw child output stays private."""
import json
from pathlib import Path


SCHEMA = json.loads((Path(__file__).resolve().parents[1] / 'web/tests/traffic-failure-schema.json').read_text())
KEYS = {'version', 'phase', 'failure_kind', 'last_http_status', 'browser_errors',
        'unexpected_proxy_connections', 'csp_violations', 'visible_rows'}


def project(raw, exit_code):
    unavailable = {'version': 1, 'browser_projection_available': False,
                   'child_exit_code': exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else None}
    try:
        if len(raw) > 4096:
            return unavailable
        def unique(pairs):
            values = {}
            for key, value in pairs:
                if key in values:
                    raise ValueError('duplicate field')
                values[key] = value
            return values
        value = json.loads(raw, object_pairs_hook=unique)
        if (not isinstance(value, dict) or set(value) != KEYS or type(value['version']) is not int
                or value['version'] != 1 or value['phase'] not in SCHEMA['phases']
                or value['failure_kind'] not in ('timeout', 'assertion', 'other')
                or type(value['last_http_status']) is not int
                or value['last_http_status'] != 0 and not 100 <= value['last_http_status'] <= 599):
            return unavailable
        for key in ('browser_errors', 'unexpected_proxy_connections'):
            if type(value[key]) is not int or not -1 <= value[key] <= 1000000:
                return unavailable
        for key in ('csp_violations', 'visible_rows'):
            if value[key] is not None and (type(value[key]) is not int or not 0 <= value[key] <= 1000000):
                return unavailable
        return {**value, 'browser_projection_available': True, 'child_exit_code': unavailable['child_exit_code']}
    except (TypeError, ValueError, KeyError, UnicodeError):
        return unavailable
