"""Build public trust messages; applying trust requires a separate verified writer."""
import re

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
