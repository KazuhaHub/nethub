"""Project a post-failure FreeBSD lock snapshot without exporting process data."""
import json
import re
import shlex
import subprocess
import sys
import tempfile
import time


LOCK_PATH = '/var/db/nethub-agent/reconcile.lock'
SCRIPT_PATH = '/usr/local/opnsense/scripts/nethub-agent/'
ACTIONS = ('reconcile', 'report', 'certificate', 'trust', 'rotate', 'watchdog',
           'start', 'stop', 'restart', 'enable', 'disable', 'unenroll', 'forget')
ROLES = tuple('agent_' + action for action in ACTIONS) + ('lock_wrapper', 'other')
STATUSES = ('complete', 'unsupported', 'unavailable', 'timeout', 'oversize', 'invalid_output')
HEADER = 'PID COMM FD T V FLAGS REF OFFSET PRO NAME'.split()


def validate(value):
    if (not isinstance(value, dict)
            or set(value) != {'version', 'status', 'held_descriptor_count', 'holder_roles',
                              'arguments_complete', 'original_failure_cause_established'}
            or type(value['version']) is not int or value['version'] != 1
            or value['status'] not in STATUSES
            or type(value['held_descriptor_count']) is not int
            or not 0 <= value['held_descriptor_count'] <= 64
            or not isinstance(value['holder_roles'], list)
            or any(not isinstance(role, str) or role not in ROLES for role in value['holder_roles'])
            or value['holder_roles'] != sorted(set(value['holder_roles']))
            or len(value['holder_roles']) > min(value['held_descriptor_count'], 4)
            or type(value['arguments_complete']) is not bool
            or value['original_failure_cause_established'] is not False
            or value['status'] != 'complete' and (value['held_descriptor_count'] != 0
                or value['holder_roles'] or value['arguments_complete'])
            or value['status'] == 'complete' and value['held_descriptor_count'] > 0
                and not value['holder_roles']):
        raise ValueError('Unexpected native lock diagnostic')


def held_descriptors(raw):
    """Accept only the documented table and exact canonical lock path."""
    lines = raw.decode('utf-8').splitlines()
    if not lines or lines[0].split() != HEADER:
        raise ValueError('Unknown descriptor table')
    found = []
    for line in lines[1:]:
        columns = line.split()
        if not columns or columns[-1] != LOCK_PATH:
            continue
        if (len(columns) != 10 or not columns[0].isdecimal()
                or not 0 < int(columns[0]) < 2**31
                or not columns[2].isdecimal() or columns[3:5] != ['v', 'r']
                or re.fullmatch('[rwasfndl-]{1,16}', columns[5]) is None):
            raise ValueError('Unknown matching descriptor')
        if 'l' in columns[5]:
            found.append(int(columns[0]))
        if len(found) > 64:
            raise ValueError('Too many matching descriptors')
    return found


def role(raw):
    try:
        words = shlex.split(raw.decode('utf-8').strip())
    except (ValueError, UnicodeError):
        return 'other'
    if words and words[0] == '/usr/bin/lockf':
        return 'lock_wrapper'
    if len(words) >= 2 and words[0] == '/usr/local/bin/python3.13':
        if len(words) == 2 and words[1] == SCRIPT_PATH + 'watchdog.py':
            return 'agent_watchdog'
        if words[1] == SCRIPT_PATH + 'agentctl.py':
            arguments = words[2:]
            if arguments[:1] == ['--locked']:
                arguments = arguments[1:]
            if len(arguments) == 1 and arguments[0] in ACTIONS:
                return 'agent_' + arguments[0]
    return 'other'


def read_command(arguments, deadline, limit):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return 'timeout', b''
    try:
        # Raw process output stays in a private temporary file, never an artifact.
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.DEVNULL, timeout=min(3, remaining), check=False)
            if result.returncode != 0:
                return 'unavailable', b''
            output.seek(0)
            raw = output.read(limit + 1)
            return ('oversize', b'') if len(raw) > limit else ('complete', raw)
    except subprocess.TimeoutExpired:
        return 'timeout', b''
    except OSError:
        return 'unavailable', b''


def inspect():
    value = {'version': 1, 'status': 'unsupported', 'held_descriptor_count': 0,
             'holder_roles': [], 'arguments_complete': False,
             'original_failure_cause_established': False}
    if not sys.platform.startswith('freebsd'):
        return value
    deadline = time.monotonic() + 8
    status, raw = read_command(['/usr/bin/procstat', '-a', '-f'], deadline, 262144)
    value['status'] = status
    if status != 'complete':
        return value
    try:
        holders = held_descriptors(raw)
    except (ValueError, UnicodeError):
        value['status'] = 'invalid_output'
        return value
    value['held_descriptor_count'] = len(holders)
    processes = sorted(set(holders))
    complete = len(processes) <= 4
    roles = set()
    for pid in processes[:4]:
        status, raw = read_command(['/bin/ps', '-p', str(pid), '-o', 'command='], deadline, 8192)
        complete = complete and status == 'complete'
        roles.add(role(raw) if status == 'complete' else 'other')
    value.update(holder_roles=sorted(roles), arguments_complete=complete)
    validate(value)
    return value


if __name__ == '__main__':
    if sys.argv[1:]:
        raise SystemExit(2)
    print(json.dumps(inspect()))
