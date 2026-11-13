"""Measure automatic native WAN recovery without restarting the agent."""
import json
from pathlib import Path
import re
import time

from guest import Guest, GuestError


PHASES = ('baseline', 'change', 'restore', 'identity', 'completed')
FLAGS = ('same_frpc_process', 'changed_source_observed', 'original_source_restored',
         'native_model_runtime_XML_and_GUI_unchanged', 'independent_original_control_and_TLS_retained')
LIMITS = ('manual_agent_start_or_reconcile', 'production_WAN_or_public_network_acceptance', 'full_W5_acceptance')


class WANError(GuestError):
    """A fixed WAN failure reason safe to retain outside the guest."""


def validate(value):
    reasons = ('wan_route_table', 'wan_route_missing', 'wan_route_mismatch', 'wan_probe',
               'process_changed', 'runtime_changed', 'native_xml_changed', 'model_or_gui_changed',
               'baseline_unavailable', 'deadline', 'restore_refused', 'invalid_observation',
               'guest_operation', 'operation_error')
    if (not isinstance(value, dict) or set(value) != set(FLAGS + LIMITS) | {
            'version', 'passed', 'phase', 'limit_ms', 'change_ms', 'restore_ms',
            'restore_attempted', 'restore_succeeded', 'failure_reason', 'restore_failure_reason'}
            or type(value['version']) is not int or value['version'] != 2
            or value['phase'] not in PHASES or type(value['passed']) is not bool
            or type(value['limit_ms']) is not int or value['limit_ms'] != 60000
            or any(type(value[key]) is not bool for key in FLAGS + LIMITS + ('restore_attempted', 'restore_succeeded'))
            or any(value[key] is not False for key in LIMITS)):
        raise ValueError('Unexpected native WAN outcome')
    if any(value[key] is not None and value[key] not in reasons
           for key in ('failure_reason', 'restore_failure_reason')):
        raise ValueError('Unexpected native WAN failure reason')
    if (value['passed'] != (value['failure_reason'] is None)
            or value['restore_failure_reason'] is not None
            and (not value['restore_attempted'] or value['restore_succeeded'])):
        raise ValueError('Inconsistent native WAN diagnostic')
    for key in ('change_ms', 'restore_ms'):
        if value[key] is not None and (type(value[key]) is not int or not 0 < value[key] <= 60000):
            raise ValueError('Unexpected native WAN timing')
    if (value['phase'] == 'completed') != value['passed']:
        raise ValueError('Inconsistent native WAN phase')
    if value['restore_succeeded'] and (not value['restore_attempted'] or value['restore_ms'] is None):
        raise ValueError('Unmeasured native WAN restoration')
    if value['passed'] and (not all(value[key] for key in FLAGS)
            or not value['restore_attempted'] or not value['restore_succeeded']
            or value['change_ms'] is None or value['restore_ms'] is None):
        raise ValueError('Incomplete native WAN success')


def projection(value):
    if (not isinstance(value, dict) or set(value) != {'address', 'pid', 'started', 'control_sources',
            'runtime_sha256', 'native_xml_sha256'}
            or value['address'] not in ('10.0.2.15', '10.0.2.16')
            or type(value['pid']) is not int or not 0 < value['pid'] < 2**31
            or not isinstance(value['started'], str) or not 0 < len(value['started']) <= 128
            or value['control_sources'] not in ([], ['10.0.2.15'], ['10.0.2.16'])
            or any(not isinstance(value[key], str) or re.fullmatch('[a-f0-9]{64}', value[key]) is None
                   for key in ('runtime_sha256', 'native_xml_sha256'))):
        raise ValueError('Unexpected private native WAN observation')
    return value


def exercise(guest, evidence, nonce, native_read, route, gui_read, check_witness, check_database):
    if not isinstance(guest, Guest) or re.fullmatch('[a-f0-9]{32}', nonce) is None:
        raise GuestError('Owned native WAN fixture required')
    result = {key: False for key in FLAGS + LIMITS}
    result.update(version=2, passed=False, phase='baseline', limit_ms=60000,
                  failure_reason=None, restore_failure_reason=None,
                  change_ms=None, restore_ms=None, restore_attempted=False, restore_succeeded=False)
    evidence = Path(evidence)
    source = Path(__file__).with_name('wan_probe.py')
    before, model, gui, failure = None, None, None, None
    changed = False

    def reason(error):
        if isinstance(error, WANError):
            return str(error)
        if isinstance(error, GuestError):
            for code in ('wan_route_table', 'wan_route_missing', 'wan_route_mismatch', 'wan_probe'):
                if str(error).endswith(' failed: fixture_' + code):
                    return code
            return 'guest_operation'
        if isinstance(error, (ValueError, TypeError, KeyError)):
            return 'invalid_observation'
        return 'operation_error'

    def probe(action):
        value = json.loads(guest.ssh('/usr/local/bin/python3.13 /root/nethub-ci/wan_probe.py '
            + action + ' ' + nonce + '\n', 'owned native WAN ' + action, timeout=35))
        if action == 'restore':
            if not isinstance(value, dict) or set(value) != {'restored'} or value['restored'] is not True:
                raise WANError('restore_refused')
            return value
        return projection(value)

    def recovered(wanted, started):
        while True:
            check_witness()
            value = probe('inspect')
            if any(value[key] != before[key] for key in ('pid', 'started')):
                raise WANError('process_changed')
            if value['runtime_sha256'] != before['runtime_sha256']:
                raise WANError('runtime_changed')
            if value['native_xml_sha256'] != before['native_xml_sha256']:
                raise WANError('native_xml_changed')
            if value['address'] == wanted and value['control_sources'] == [wanted] and route():
                elapsed = time.monotonic() - started
                if elapsed > 60:
                    raise WANError('deadline')
                return max(1, round(elapsed * 1000))
            if time.monotonic() - started >= 60:
                raise WANError('deadline')
            time.sleep(.25)

    errors = (GuestError, OSError, ValueError, TypeError, KeyError)
    try:
        try:
            guest.put(source, 'wan_probe.py')
            before = probe('inspect')
            if before['address'] != '10.0.2.15' or before['control_sources'] != ['10.0.2.15'] or not route():
                raise WANError('baseline_unavailable')
            model = native_read('native-wan-before-private.json')
            gui = gui_read()
            check_witness()
            check_database()
            result['phase'] = 'change'
            started = time.monotonic()
            changed = True
            probe('change')
            result['change_ms'] = recovered('10.0.2.16', started)
        except errors as error:
            failure = result['phase']
            result['failure_reason'] = reason(error)
        finally:
            if changed:
                result['restore_attempted'] = True
                result['phase'] = 'restore'
                started = time.monotonic()
                try:
                    probe('restore')
                    result['restore_ms'] = recovered('10.0.2.15', started)
                    result['restore_succeeded'] = True
                except errors as error:
                    failure = failure or 'restore'
                    result['restore_failure_reason'] = reason(error)
                    result['failure_reason'] = result['failure_reason'] or reason(error)
        if failure is None:
            result['phase'] = 'identity'
            try:
                if native_read('native-wan-after-private.json') != model or gui_read() != gui:
                    raise WANError('model_or_gui_changed')
                check_witness()
                check_database()
                result.update({key: True for key in FLAGS})
                result.update(passed=True, phase='completed')
            except errors as error:
                failure = 'identity'
                result['failure_reason'] = reason(error)
        if failure is not None:
            result['phase'] = failure
    finally:
        validate(result)
        path = evidence / 'installed-wan-recovery.json'
        path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        path.chmod(0o600)
    if not result['passed']:
        raise GuestError('Native WAN recovery failed at ' + result['phase'])
    return result
