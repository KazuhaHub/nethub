"""Require bounded read-only readiness after the original WAN restoration."""
import json
from pathlib import Path
import time

from guest import GuestError


LIMIT_MS = 60000
STABLE_MS = 15000
GAP_MS = 1000
STATES = ('ready', 'route_missing', 'not_ready')
PHASES = ('observing', 'completed', 'deadline', 'observation', 'clock')
COUNTERS = ('elapsed_ms', 'stable_ms', 'samples', 'missing_route_samples',
            'not_ready_samples', 'window_max_gap_ms')


def validate(value):
    if (not isinstance(value, dict) or set(value) != set(COUNTERS) | {
            'version', 'passed', 'phase', 'limit_ms', 'required_stable_ms',
            'maximum_sample_gap_ms', 'read_only_observation',
            'network_or_package_operation_replayed', 'public_or_release_accepted'}
            or type(value['version']) is not int or value['version'] != 1
            or type(value['passed']) is not bool or value['phase'] not in PHASES
            or value['passed'] != (value['phase'] == 'completed')
            or any(type(value[key]) is not int or not 0 <= value[key] <= 300000 for key in COUNTERS)
            or any(type(value[key]) is not int or value[key] != expected for key, expected in (
                ('limit_ms', LIMIT_MS), ('required_stable_ms', STABLE_MS),
                ('maximum_sample_gap_ms', GAP_MS)))
            or value['read_only_observation'] is not True
            or value['network_or_package_operation_replayed'] is not False
            or value['public_or_release_accepted'] is not False
            or value['missing_route_samples'] + value['not_ready_samples'] > value['samples']):
        raise ValueError('Unexpected WAN settling evidence')
    if value['passed'] and (not STABLE_MS <= value['stable_ms'] <= value['elapsed_ms'] <= LIMIT_MS
            or value['window_max_gap_ms'] > GAP_MS or value['samples'] < 2):
        raise ValueError('Incomplete WAN settling evidence')


def settle(evidence, restore_started, observe):
    """Observe the same operation; never repair a route or repeat a mutation."""
    path = Path(evidence) / 'installed-wan-settling.json'
    value = dict.fromkeys(COUNTERS, 0)
    value.update(version=1, passed=False, phase='observing', limit_ms=LIMIT_MS,
                 required_stable_ms=STABLE_MS, maximum_sample_gap_ms=GAP_MS,
                 read_only_observation=True, network_or_package_operation_replayed=False,
                 public_or_release_accepted=False)
    # An existing record belongs to an earlier attempt, not permission to retry.
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output)
    path.chmod(0o600)
    stable_since, previous = None, restore_started
    try:
        while True:
            stamp = time.monotonic()
            if stamp < previous:
                value['phase'] = 'clock'
                raise GuestError('Native WAN settling clock changed')
            value['elapsed_ms'] = round((stamp - restore_started) * 1000)
            if (stamp - restore_started) * 1000 >= LIMIT_MS:
                value['phase'] = 'deadline'
                raise GuestError('Native WAN did not settle within its original restoration budget')
            try:
                state = observe()
                if state not in STATES:
                    raise ValueError('Unexpected WAN readiness projection')
            except Exception:
                value['phase'] = 'observation'
                raise
            stamp = time.monotonic()
            if stamp < previous:
                value['phase'] = 'clock'
                raise GuestError('Native WAN settling clock changed')
            gap = (stamp - previous) * 1000
            value['elapsed_ms'] = round((stamp - restore_started) * 1000)
            value['samples'] += 1
            if value['elapsed_ms'] > LIMIT_MS:
                value['phase'] = 'deadline'
                raise GuestError('Native WAN readiness observation exceeded its original budget')
            if state == 'route_missing':
                value['missing_route_samples'] += 1
            elif state == 'not_ready':
                value['not_ready_samples'] += 1
            if state != 'ready' or gap > GAP_MS:
                stable_since = None
                value['stable_ms'] = value['window_max_gap_ms'] = 0
            elif stable_since is None:
                stable_since = stamp
                value['window_max_gap_ms'] = 0
            else:
                value['window_max_gap_ms'] = max(value['window_max_gap_ms'], round(gap))
                value['stable_ms'] = int((stamp - stable_since) * 1000)
            previous = stamp
            if value['stable_ms'] >= STABLE_MS:
                value.update(passed=True, phase='completed')
                return value
            time.sleep(.25)
    finally:
        validate(value)
        path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
        path.chmod(0o600)
