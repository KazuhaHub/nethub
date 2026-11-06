"""Validate the closed public recovery result without copying private fields."""
import re

from cold_operation import FILES, PHASES, PROOFS, TIMINGS


def validate_operation(value, head):
    common = {'version', 'source_head', 'passed'}
    if (not isinstance(value, dict) or type(value.get('version')) is not int or value['version'] != 1
            or value.get('source_head') != head or type(value.get('passed')) is not bool
            or re.fullmatch('[a-f0-9]{40}', head) is None):
        raise ValueError('Exact closed operation result required')
    if value['passed']:
        limit = 'public_operator_durable_custody_renewal_clock_or_full_goal_accepted'
        if (set(value) != common | set(PROOFS) | set(TIMINGS) | {limit}
                or any(value[key] is not True for key in PROOFS) or value[limit] is not False
                or any(type(value[key]) is not int or not 0 < value[key] <= 7200000 for key in TIMINGS)):
            raise ValueError('Full isolated success proof shape differs')
    else:
        if (set(value) != common | {'phase', 'failure_kind', 'locations', 'full_recovery_or_goal_accepted'}
                or value['phase'] not in (*PHASES, 'unavailable') or value['failure_kind'] not in ('timeout', 'other')
                or value['full_recovery_or_goal_accepted'] is not False or not isinstance(value['locations'], list)
                or len(value['locations']) > 16):
            raise ValueError('Closed failure proof shape differs')
        for frame in value['locations']:
            if (not isinstance(frame, dict) or set(frame) != {'source', 'line'} or frame['source'] not in FILES
                    or type(frame['line']) is not int or not 1 <= frame['line'] <= 20000):
                raise ValueError('Closed failure location refused')
    return value


def validate_cleanup(value, head):
    proofs = {'operation_cgroup_reaped', 'owned_private_VM_disks_keys_and_logs_removed',
              'owned_witness_removed_or_never_started'}
    if (not isinstance(value, dict) or set(value) != proofs | {'version', 'source_head', 'witness_was_started',
            'full_recovery_or_goal_accepted'} or type(value['version']) is not int or value['version'] != 1
            or value['source_head'] != head or any(value[key] is not True for key in proofs)
            or type(value['witness_was_started']) is not bool or value['full_recovery_or_goal_accepted'] is not False):
        raise ValueError('Closed owned cleanup result required')
    return value
