"""Require bounded read-only readiness after the original WAN restoration."""
import json
from pathlib import Path
import time

from guest import GuestError, SETTLE_OBSERVER_TRANSPORT_KINDS


LIMIT_MS = 60000
STABLE_MS = 15000
GAP_MS = 1000
STATES = ('ready', 'route_missing', 'not_ready', 'observer_restarted', 'observer_lost')
PHASES = ('observing', 'completed', 'deadline', 'observation', 'clock', 'observer_lost')
COUNTERS = ('elapsed_ms', 'stable_ms', 'samples', 'missing_route_samples',
            'not_ready_samples', 'window_max_gap_ms')
OBSERVER_COUNTERS = ('observer_restarts', 'last_observer_recovery_ms', 'observer_recovery_failures')
MAX_OBSERVER_RESTARTS = 2
VERSIONS = (1, 2)
RECOVERY_KEYS = {'first_transport_failure', 'sshd_pid_state', 'sshd_log_category',
                 'listener_recovery', 'started_ms', 'elapsed_ms'}


def validate_observer_recovery(item):
    if (not isinstance(item, dict) or set(item) != RECOVERY_KEYS
            or item['first_transport_failure'] not in SETTLE_OBSERVER_TRANSPORT_KINDS
            or item['sshd_pid_state'] != 'dead'
            or item['sshd_log_category'] not in ('sigterm', 'none', 'other')
            or item['listener_recovery'] != 'started_and_verified'
            or any(type(item[key]) is not int or not 0 <= item[key] <= 300000
                   for key in ('started_ms', 'elapsed_ms'))
            or item['started_ms'] > item['elapsed_ms']):
        raise ValueError('Unexpected WAN observer recovery evidence')


def validate(value):
    version = value.get('version') if isinstance(value, dict) else None
    if type(version) is not int or version not in VERSIONS:
        raise ValueError('Unexpected WAN settling evidence')
    extra = set(OBSERVER_COUNTERS) | {'observer_recoveries'} if version == 2 else set()
    if (set(value) != set(COUNTERS) | extra | {
            'version', 'passed', 'phase', 'limit_ms', 'required_stable_ms',
            'maximum_sample_gap_ms', 'read_only_observation',
            'network_or_package_operation_replayed', 'public_or_release_accepted'}
            or type(value['passed']) is not bool or value['phase'] not in PHASES
            or value['passed'] != (value['phase'] == 'completed')
            or (version == 1 and value['phase'] == 'observer_lost')
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
    if version == 1:
        return
    restarts, last = value['observer_restarts'], value['last_observer_recovery_ms']
    recoveries = value['observer_recoveries']
    failures = value['observer_recovery_failures']
    # A third loss is retained as the terminal observer_lost failure; it is never restarted.
    lost = value['phase'] == 'observer_lost'
    if (type(restarts) is not int or not 0 <= restarts <= MAX_OBSERVER_RESTARTS
            or (lost and restarts != MAX_OBSERVER_RESTARTS)
            or type(failures) is not int or not 0 <= failures <= 1
            or (failures and value['phase'] != 'observation')
            or type(last) is not int or not 0 <= last <= 300000
            or (last == 0) != (restarts == 0)
            or not isinstance(recoveries, list) or len(recoveries) != restarts):
        raise ValueError('Unexpected WAN observer restart evidence')
    for item in recoveries:
        validate_observer_recovery(item)
    if any(item['started_ms'] < previous['elapsed_ms']
           for previous, item in zip(recoveries, recoveries[1:])):
        raise ValueError('Unordered WAN observer recovery evidence')
    if recoveries and (recoveries[-1]['elapsed_ms'] > last):
        raise ValueError('Inconsistent WAN observer recovery evidence')
    if value['passed'] and last > value['elapsed_ms'] - value['stable_ms']:
        raise ValueError('WAN settling window overlaps an observer restart')


def settle(evidence, restore_started, observe, recoveries=None, recovery_failures=None):
    """Observe the same operation; never repair a route or repeat a mutation."""
    path = Path(evidence) / 'installed-wan-settling.json'
    value = dict.fromkeys(COUNTERS, 0)
    recoveries = [] if recoveries is None else recoveries
    recovery_failures = [] if recovery_failures is None else recovery_failures
    value.update(version=2, observer_restarts=0, last_observer_recovery_ms=0, observer_recovery_failures=0,
                 observer_recoveries=[],
                 passed=False, phase='observing', limit_ms=LIMIT_MS,
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
            if state == 'observer_lost':
                value['phase'] = 'observer_lost'
                raise GuestError('Native WAN observer was lost repeatedly during settling')
            if state == 'observer_restarted':
                # The fifteen-second window must lie entirely after the last restart.
                value['last_observer_recovery_ms'] = value['elapsed_ms']
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
        # Derived from the recorded restarts so both records agree on every path.
        value['observer_restarts'] = len(recoveries)
        value['observer_recoveries'] = [dict(item) for item in recoveries]
        value['observer_recovery_failures'] = min(len(recovery_failures), 1)
        if recoveries:
            value['last_observer_recovery_ms'] = max(value['last_observer_recovery_ms'],
                                                     recoveries[-1]['elapsed_ms'], 1)
        validate(value)
        path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
        path.chmod(0o600)
