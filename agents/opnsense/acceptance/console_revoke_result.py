"""Validate the bounded native console-Revoke receipt without private payloads."""
from datetime import datetime, timedelta


BROWSER_FIELDS = frozenset(('version', 'passed', 'phase', 'deadline_ms', 'clock_start',
    'isolated_console_CA_exception', 'public_network_acceptance', 'full_W5_acceptance',
    'samples', 'confirmation_dispatch_utc', 'console_response_ms', 'server_revoked_at_utc',
    'native_proxy_offline_ms', 'normal_browser_CSRF_protected_revoke',
    'no_reconnect_observation_ms', 'csp_violations', 'browser_errors', 'external_requests'))
NATIVE_FIELDS = frozenset(('native_identity_and_grants_retained',
    'fresh_verified_native_route_refused', 'independent_original_control_and_verified_TLS_retained',
    'valid_source_grant_retained_during_TLS_refusal'))


def validate(value, *, native=False):
    if not isinstance(value, dict) or set(value) != BROWSER_FIELDS | (NATIVE_FIELDS if native else frozenset()):
        raise ValueError('Exact console Revoke receipt fields required')
    if (type(value['version']) is not int or value['version'] != 1
            or value['passed'] is not True or value['phase'] != 'completed'
            or type(value['deadline_ms']) is not int or value['deadline_ms'] != 5000
            or value['clock_start'] != 'before normal console confirmation click'
            or value['isolated_console_CA_exception'] is not True
            or value['public_network_acceptance'] is not False or value['full_W5_acceptance'] is not False
            or value['normal_browser_CSRF_protected_revoke'] is not True):
        raise ValueError('Console dispatch scope and completed outcome required')
    for key, low, high in [('native_proxy_offline_ms', 1, 5000), ('console_response_ms', 1, 15000),
                           ('no_reconnect_observation_ms', 30000, 60000),
                           ('csp_violations', 0, 0), ('browser_errors', 0, 0), ('external_requests', 0, 0)]:
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError('Console Revoke timing or browser bounds differ')
    for key in ('confirmation_dispatch_utc', 'server_revoked_at_utc'):
        text = value[key]
        if not isinstance(text, str) or not 20 <= len(text) <= 40:
            raise ValueError('Bounded UTC event time required')
        try:
            stamp = datetime.fromisoformat(text)
        except ValueError:
            raise ValueError('UTC event time format invalid') from None
        if stamp.tzinfo is None or stamp.utcoffset() != timedelta(0):
            raise ValueError('UTC event time required')
    samples = value['samples']
    if not isinstance(samples, list) or not 2 <= len(samples) <= 100:
        raise ValueError('Live baseline and actual offline samples required')
    previous = -1
    for index, sample in enumerate(samples):
        if (not isinstance(sample, dict) or set(sample) != {'elapsed_ms', 'proxy_online'}
                or type(sample['elapsed_ms']) is not int or not previous <= sample['elapsed_ms'] <= 5000
                or sample['elapsed_ms'] < 0 or type(sample['proxy_online']) is not bool
                or sample['proxy_online'] is not (index < len(samples) - 1)):
            raise ValueError('Bounded ordered original proxy observations required')
        previous = sample['elapsed_ms']
    if previous != value['native_proxy_offline_ms']:
        raise ValueError('Cutoff must match the actual offline observation')
    if native and any(value[key] is not True for key in NATIVE_FIELDS):
        raise ValueError('Installed identity, TLS refusal and survivor proofs required')
    return value
