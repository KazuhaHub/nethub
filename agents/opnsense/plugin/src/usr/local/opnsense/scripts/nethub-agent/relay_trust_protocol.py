"""Build public trust messages; applying trust requires a separate verified writer."""
import re
from datetime import datetime, timezone

from enrollment import _SEMVER
from lifecycle import identity
from protocol import ProtocolError


def settings_request(device_id):
    return identity(device_id)


def applied_request(device_id, generation_id, generation, bundle_fingerprint):
    body = identity(device_id)
    if (not isinstance(generation_id, str)
            or not re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', generation_id)
            or generation_id == '00000000-0000-0000-0000-000000000000'
            or type(generation) is not int or not 1 <= generation <= 2147483647
            or not isinstance(bundle_fingerprint, str)
            or not re.fullmatch(r'[a-f0-9]{64}', bundle_fingerprint)):
        raise ProtocolError('Invalid relay trust application identity')
    body.update(generation_id=generation_id, generation=generation, bundle_fingerprint=bundle_fingerprint)
    return body


def _invalid():
    raise ProtocolError('Invalid relay trust response')


def _response(value, device_id, fields):
    settings_request(device_id)
    if (not isinstance(value, dict) or not fields <= value.keys() or len(value) > len(fields) + 16
            or not isinstance(value['agent_protocol_version'], str)
            or len(value['agent_protocol_version']) > 64 or not _SEMVER.fullmatch(value['agent_protocol_version'])
            or value['agent_protocol_version'].split('.')[0] != '1'
            or value['agent_protocol_version'].split('.')[1] in ('0', '1', '2', '3', '4')
            or value['device_id'] != device_id):
        _invalid()
    return {key: value[key] for key in fields}


def _stamp(value):
    if not isinstance(value, str) or len(value) != 27:
        _invalid()
    try:
        stamp = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
        if stamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ') != value:
            _invalid()
        return stamp
    except ValueError:
        _invalid()


def applied_response(value, request):
    """Correlate an acceptance with the exact report, independently of receipt time."""
    expected = applied_request(request['device_id'], request['generation_id'], request['generation'], request['bundle_fingerprint'])
    fields = set(expected) | {'accepted', 'accepted_at'}
    result = _response(value, expected['device_id'], fields)
    applied_request(result['device_id'], result['generation_id'], result['generation'], result['bundle_fingerprint'])
    if result['accepted'] is not True or any(result[key] != expected[key] for key in expected if key != 'agent_protocol_version'):
        _invalid()
    _stamp(result['accepted_at'])
    return result
