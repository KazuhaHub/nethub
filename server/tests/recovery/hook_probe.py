"""Count only fixed connection-hook decisions from private bounded service logs."""
import json


DECISIONS = ('allowed', 'device_denied', 'unavailable', 'busy', 'invalid_request',
             'invalid_claim', 'proxy_policy', 'connection_policy')


def project(raw):
    message = 'Restored connection-hook observation unavailable'
    if not isinstance(raw, bytes) or len(raw) > 256 * 1024 or len(raw.splitlines()) > 1024:
        raise ValueError(message)
    counts = dict.fromkeys(DECISIONS, 0)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(message)
            value[key] = item
        return value
    for line in raw.splitlines():
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
    return {'version': 1, 'connection_decisions': counts}
