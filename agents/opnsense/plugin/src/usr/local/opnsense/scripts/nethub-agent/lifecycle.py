"""Send bounded health/removal messages; PHP remains the configuration writer."""
from datetime import datetime, timezone
import re

from enrollment import _SEMVER, _UUID, request_json
from protocol import ProtocolError, VERSION


def identity(device_id):
    if not isinstance(device_id, str) or not _UUID.fullmatch(device_id):
        raise ProtocolError('Invalid device identity')
    return {'agent_protocol_version': VERSION, 'device_id': device_id}


def acknowledgement(value, device_id, action):
    fields = ('agent_protocol_version', 'device_id', 'revoked') + (('accepted',) if action == 'status' else ())
    if (not isinstance(value, dict) or len(value) > len(fields) + 16
            or any(key not in value for key in fields)
            or not isinstance(value['agent_protocol_version'], str)
            or len(value['agent_protocol_version']) > 64 or not _SEMVER.fullmatch(value['agent_protocol_version'])
            or value['agent_protocol_version'].split('.')[0] != '1'
            or value['device_id'] != device_id or type(value['revoked']) is not bool
            or action == 'status' and value['accepted'] is not True
            or action == 'unenroll' and value['revoked'] is not True):
        raise ProtocolError('Invalid device acknowledgement')
    return {key: value[key] for key in fields}


def request_removal(origin, secret, device_id, context=None):
    body = identity(device_id)
    return acknowledgement(request_json(origin, '/api/v1/devices/unenroll', body, secret=secret, context=context), device_id, 'unenroll')


def health_request(device_id, platform_version, agent_version, service_state, reconcile):
    body = identity(device_id)
    for value in (platform_version, agent_version):
        if not isinstance(value, str) or len(value) > 128 or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise ProtocolError('Invalid health metadata')
    if service_state not in ('running', 'stopped', 'disabled', 'error'):
        raise ProtocolError('Invalid health state')
    success = stamp = None
    if isinstance(reconcile, dict) and type(reconcile.get('success')) is bool:
        try:
            value = reconcile['updated_at']
            if not isinstance(value, str) or len(value) > 40 or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)', value):
                raise ValueError()
            parsed = datetime.fromisoformat(value)
            stamp = parsed.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            success = reconcile['success']
        except (KeyError, TypeError, ValueError):
            pass
    body.update(platform_version=platform_version, agent_version=agent_version, service_state=service_state,
                last_reconcile_success=success, last_reconcile_at=stamp)
    return body


def report_health(origin, secret, body, context=None):
    return acknowledgement(request_json(origin, '/api/v1/devices/status', body, secret=secret, context=context), body['device_id'], 'status')
