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


def validate(value):
    if (not isinstance(value, dict) or set(value) != set(FLAGS + LIMITS) | {
            'version', 'passed', 'phase', 'limit_ms', 'change_ms', 'restore_ms',
            'restore_attempted', 'restore_succeeded'}
            or type(value['version']) is not int or value['version'] != 1
            or value['phase'] not in PHASES or type(value['passed']) is not bool
            or type(value['limit_ms']) is not int or value['limit_ms'] != 60000
            or any(type(value[key]) is not bool for key in FLAGS + LIMITS + ('restore_attempted', 'restore_succeeded'))
            or any(value[key] is not False for key in LIMITS)):
        raise ValueError('Unexpected native WAN outcome')
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
    result.update(version=1, passed=False, phase='baseline', limit_ms=60000,
                  change_ms=None, restore_ms=None, restore_attempted=False, restore_succeeded=False)
    evidence = Path(evidence)
    source = Path(__file__).with_name('wan_probe.py')
    before, model, gui, failure = None, None, None, None
    changed = False

    def probe(action):
        value = json.loads(guest.ssh('/usr/local/bin/python3.13 /root/nethub-ci/wan_probe.py '
            + action + ' ' + nonce + '\n', 'owned native WAN ' + action, timeout=35))
        if action == 'restore':
            if not isinstance(value, dict) or set(value) != {'restored'} or value['restored'] is not True:
                raise GuestError('Owned WAN restoration refused')
            return value
        return projection(value)

    def recovered(wanted, started):
        while True:
            check_witness()
            value = probe('inspect')
            if any(value[key] != before[key] for key in ('pid', 'started', 'runtime_sha256', 'native_xml_sha256')):
                raise GuestError('Native WAN recovery changed its original process or configuration')
            if value['address'] == wanted and value['control_sources'] == [wanted] and route():
                elapsed = time.monotonic() - started
                if elapsed > 60:
                    raise GuestError('Native WAN recovery observed after deadline')
                return max(1, round(elapsed * 1000))
            if time.monotonic() - started >= 60:
                raise GuestError('Native WAN automatic recovery exceeded deadline')
            time.sleep(.25)

    errors = (GuestError, OSError, ValueError, TypeError, KeyError)
    try:
        try:
            guest.put(source, 'wan_probe.py')
            before = probe('inspect')
            if before['address'] != '10.0.2.15' or before['control_sources'] != ['10.0.2.15'] or not route():
                raise GuestError('Original native WAN route unavailable')
            model = native_read('native-wan-before-private.json')
            gui = gui_read()
            check_witness()
            check_database()
            result['phase'] = 'change'
            started = time.monotonic()
            changed = True
            probe('change')
            result['change_ms'] = recovered('10.0.2.16', started)
        except errors:
            failure = result['phase']
        finally:
            if changed:
                result['restore_attempted'] = True
                result['phase'] = 'restore'
                started = time.monotonic()
                try:
                    probe('restore')
                    result['restore_ms'] = recovered('10.0.2.15', started)
                    result['restore_succeeded'] = True
                except errors:
                    failure = failure or 'restore'
        if failure is None:
            result['phase'] = 'identity'
            try:
                if native_read('native-wan-after-private.json') != model or gui_read() != gui:
                    raise GuestError('Native WAN recovery changed the model or GUI')
                check_witness()
                check_database()
                result.update({key: True for key in FLAGS})
                result.update(passed=True, phase='completed')
            except errors:
                failure = 'identity'
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
