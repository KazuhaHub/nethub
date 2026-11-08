"""Retain only closed, read-only issuer status when cold issuance times out."""
import json
import re
import uuid


ENUMS = {
    'job_state': ('queued', 'leased', 'retry_wait', 'failed', 'cancelled', 'issued', 'missing', 'unavailable'),
    'failure_code': ('none', 'transient', 'policy', 'indeterminate_order', 'job_expired',
                     'lease_exhausted', 'attempts_exhausted', 'polls_exhausted', 'assignment_changed',
                     'missing', 'unavailable'),
    'progress_phase': ('order_intent', 'order_saved', 'proof_saved', 'proof_live', 'validating',
                       'finalizing', 'none', 'unavailable'),
    'issuer_active': ('active', 'reloading', 'inactive', 'failed', 'activating', 'deactivating', 'maintenance', 'unavailable'),
    'issuer_result': ('success', 'resources', 'timeout', 'exit-code', 'signal', 'core-dump',
                      'watchdog', 'start-limit-hit', 'oom-kill', 'protocol', 'unavailable'),
}
ENUMS['issuer_timer_active'] = ENUMS['cleanup_timer_active'] = ENUMS['issuer_active']
BOOLEANS = ('db_observed', 'job_present', 'lease_present', 'lease_expired', 'deadline_expired',
            'retry_due', 'generation_present', 'issuer_started', 'issuer_finished')
COUNTERS = {'failures': 5, 'recoveries': 3, 'polls': 60, 'issuer_exit': 255}
DB_KEYS = {'job_state', 'failure_code', 'progress_phase', 'failures', 'recoveries', 'polls',
           'lease_present', 'lease_expired', 'deadline_expired', 'retry_due', 'generation_present'}
SERVICE_PROPERTIES = ('ActiveState', 'Result', 'ExecMainStatus', 'ExecMainStartTimestampMonotonic',
                      'ExecMainExitTimestampMonotonic')


def validate_status(value):
    if not isinstance(value, dict) or set(value) != set(ENUMS) | set(BOOLEANS) | set(COUNTERS):
        raise ValueError('Closed issuer observation shape required')
    if (any(not isinstance(value[key], str) or value[key] not in choices for key, choices in ENUMS.items())
            or any(type(value[key]) is not bool for key in BOOLEANS)
            or any(type(value[key]) is not int or not -1 <= value[key] <= limit for key, limit in COUNTERS.items())):
        raise ValueError('Closed issuer observation values required')
    return dict(value)


def unavailable():
    return {**dict.fromkeys(ENUMS, 'unavailable'), **dict.fromkeys(BOOLEANS, False),
            **dict.fromkeys(COUNTERS, -1)}


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate observation field')
        value[key] = item
    return value


def database_status(raw):
    result = unavailable()
    if not isinstance(raw, str) or len(raw) > 2048:
        raise ValueError('Bounded database observation required')
    if raw:
        row = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(row, dict) or set(row) != DB_KEYS:
            raise ValueError('Closed database observation required')
        result.update(row)
        result['job_present'] = True
        validate_status(result)
        # Missing is reserved for the absence of a row, not a stored state.
        if row['job_state'] not in ENUMS['job_state'][:-2] or row['failure_code'] not in ENUMS['failure_code'][:-2]:
            raise ValueError('Known stored job state required')
        if row['progress_phase'] == 'unavailable' or any(row[key] < 0 for key in ('failures', 'recoveries', 'polls')):
            raise ValueError('Complete stored job observation required')
    else:
        result.update(job_state='missing', failure_code='missing', progress_phase='none')
    result['db_observed'] = True
    return validate_status(result)


def service_status(raw):
    if not isinstance(raw, bytes) or len(raw) > 2048:
        raise ValueError('Bounded service observation required')
    rows = raw.decode('ascii').splitlines()
    if len(rows) != len(SERVICE_PROPERTIES) or any('=' not in row for row in rows):
        raise ValueError('Exact service properties required')
    value = unique_object(row.split('=', 1) for row in rows)
    if set(value) != set(SERVICE_PROPERTIES):
        raise ValueError('Exact service properties required')
    numeric = ('ExecMainStatus', 'ExecMainStartTimestampMonotonic', 'ExecMainExitTimestampMonotonic')
    if any(re.fullmatch('[0-9]{1,20}', value[key]) is None for key in numeric):
        raise ValueError('Bounded service counters required')
    result = unavailable()
    result.update(issuer_active=value['ActiveState'], issuer_result=value['Result'],
                  issuer_exit=int(value['ExecMainStatus']),
                  issuer_started=int(value['ExecMainStartTimestampMonotonic']) > 0,
                  issuer_finished=int(value['ExecMainExitTimestampMonotonic']) > 0)
    return validate_status(result)


def collect_status(host, device, request):
    result = unavailable()
    try:
        if any(not isinstance(item, str) or str(uuid.UUID(item)) != item for item in (device, request)):
            return result
    except (ValueError, TypeError, AttributeError):
        return result
    try:
        query = ("SELECT jsonb_build_object('job_state',j.state,'failure_code',j.failure_code,"
                 "'progress_phase',coalesce(p.phase,'none'),'failures',j.failures,'recoveries',j.recoveries,"
                 "'polls',j.polls,'lease_present',j.lease_expires_at IS NOT NULL,"
                 "'lease_expired',coalesce(j.lease_expires_at<=statement_timestamp(),false),"
                 "'deadline_expired',j.deadline<=statement_timestamp(),'retry_due',j.next_attempt_at<=statement_timestamp(),"
                 "'generation_present',EXISTS(SELECT 1 FROM gui_certificate_generations g WHERE g.job_id=j.id))::text "
                 "FROM gui_certificate_jobs j LEFT JOIN gui_certificate_progress p ON p.job_id=j.id "
                 "WHERE j.device_id='" + device + "' AND j.request_id='" + request + "' AND j.generation=1")
        observed = database_status(host.query(query))
        result.update({key: observed[key] for key in DB_KEYS | {'db_observed', 'job_present'}})
    except Exception:
        # Read-only diagnostics must not replace the original failed operation.
        pass
    try:
        observed = service_status(host.remote(
            ['/usr/bin/systemctl', 'show', 'nethub-gui-issuer.service',
             '--property=' + ','.join(SERVICE_PROPERTIES)], 'Closed issuer timeout service observation', timeout=10))
        keys = {'issuer_active', 'issuer_result', 'issuer_exit', 'issuer_started', 'issuer_finished'}
        result.update({key: observed[key] for key in keys})
    except Exception:
        pass
    for key, unit in (('issuer_timer_active', 'nethub-gui-issuer.timer'),
                      ('cleanup_timer_active', 'nethub-http01-cleanup.timer')):
        try:
            raw = host.remote(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState', '--value'],
                              'Closed issuer timeout timer observation', timeout=10)
            if not isinstance(raw, bytes) or len(raw) > 64:
                raise ValueError('Bounded timer state required')
            state = raw.decode('ascii').strip()
            if state not in ENUMS[key]:
                raise ValueError('Known timer state required')
            result[key] = state
        except Exception:
            pass
    return validate_status(result)
