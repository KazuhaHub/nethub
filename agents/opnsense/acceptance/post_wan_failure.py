"""Retain closed read-only observations without accepting a failed WAN preflight."""
import json
import os
from pathlib import Path
import re
import subprocess
import time

from guest import GuestError, validate_ssh_failure_kind
from package_probe import validate as validate_package_probe
from console_probe import validate_result as validate_console_probe


def validate(value):
    if (not isinstance(value, dict) or set(value) != {
            'version', 'source_head', 'diagnostic_only', 'failure_overridden', 'guest', 'host', 'elapsed_ms'}
            or value['version'] != 1 or type(value['version']) is not int
            or not isinstance(value['source_head'], str) or not re.fullmatch('[a-f0-9]{40}', value['source_head'])
            or value['diagnostic_only'] is not True or value['failure_overridden'] is not False
            or type(value['elapsed_ms']) is not int or not 0 <= value['elapsed_ms'] <= 300000):
        raise ValueError('Unexpected post-WAN diagnostic')
    guest, host = value['guest'], value['host']
    if (not isinstance(guest, dict) or set(guest) != {'kind', 'client_running', 'control_present'}
            or not isinstance(guest['kind'], str)):
        raise ValueError('Unexpected closed guest observation')
    if guest['kind'] == 'verified':
        if any(type(guest[k]) is not bool for k in ('client_running', 'control_present')):
            raise ValueError('Unexpected verified package observation')
        if guest['control_present'] and not guest['client_running']:
            raise ValueError('Stopped client cannot retain a control')
    else:
        validate_ssh_failure_kind(guest['kind'])
        if guest['client_running'] is not None or guest['control_present'] is not None:
            raise ValueError('Failed package observation cannot retain process flags')
    if (not isinstance(host, dict) or set(host) != {'curl_exit', 'http_status', 'verified'}
            or host['curl_exit'] is not None and (type(host['curl_exit']) is not int or not 0 <= host['curl_exit'] <= 255)
            or type(host['http_status']) is not int
            or not (host['http_status'] == 0 or 100 <= host['http_status'] <= 599)
            or type(host['verified']) is not bool
            or host['verified'] != (host['curl_exit'] == 0 and host['http_status'] == 200)):
        raise ValueError('Unexpected closed host observation')


def observe_guest(guest, nonce):
    result = {'kind': 'unclassified', 'client_running': None, 'control_present': None}
    try:
        raw = guest.ssh_read_only_inspection(
            '/usr/local/bin/python3.13 /root/nethub-ci/package_probe.py ' + nonce + '\n')
        value = json.loads(raw)
        validate_package_probe(value)
        result.update(kind='verified', client_running=value['running'], control_present=value['control_sha256'] is not None)
    except GuestError as error:
        prefix = 'native package snapshot failed: '
        if str(error).startswith(prefix):
            try:
                code = validate_ssh_failure_kind(str(error)[len(prefix):])
                result['kind'] = code
            except ValueError:
                pass
    except (OSError, ValueError, TypeError, KeyError):
        pass
    return result


def observe_host(stage, port):
    result = {'curl_exit': None, 'http_status': 0, 'verified': False}
    try:
        response = subprocess.run(['curl', '--silent', '--show-error', '--noproxy', '*', '--max-time', '10',
            '--cacert', str(stage / 'console-ca.pem'), '--connect-to',
            'console.example.com:443:127.0.0.1:' + str(port), '--output', '/dev/null', '--write-out', '%{http_code}',
            'https://console.example.com/'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12)
        if type(response.returncode) is int and 0 <= response.returncode <= 255:
            result['curl_exit'] = response.returncode
        if isinstance(response.stdout, bytes) and re.fullmatch(b'[1-5][0-9]{2}', response.stdout):
            result['http_status'] = int(response.stdout)
        result['verified'] = result['curl_exit'] == 0 and result['http_status'] == 200
    except (OSError, subprocess.SubprocessError):
        pass
    return result


def retain(guest, stage, port, evidence, nonce, head):
    stage, evidence = Path(stage), Path(evidence)
    if (stage.parent not in (Path('/tmp'), Path('/var/tmp')) or stage.resolve() != stage
            or type(port) is not int or not 1 <= port <= 65535
            or not isinstance(nonce, str) or not re.fullmatch('[a-f0-9]{32}', nonce)
            or not isinstance(head, str) or not re.fullmatch('[a-f0-9]{40}', head)
            or evidence.resolve() != evidence):
        raise ValueError('Owned post-WAN diagnostic context required')
    started = time.monotonic()
    # Inspect the guest first, while retaining the original failed outcome.
    # The existing narrow SSH transport-recovery allowance is unchanged.
    value = {'version': 1, 'source_head': head, 'diagnostic_only': True, 'failure_overridden': False,
             'guest': observe_guest(guest, nonce), 'host': observe_host(stage, port),
             'elapsed_ms': round((time.monotonic() - started) * 1000)}
    validate(value)
    with (evidence / 'post-wan-console-failure.json').open('x') as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output, sort_keys=True)
    return value


def refuse(probe, guest, stage, port, evidence, nonce, head):
    validate_console_probe(probe)
    if probe['passed']:
        raise ValueError('Only a failed post-WAN console probe can be refused')
    try:
        retain(guest, stage, port, evidence, nonce, head)
    except Exception:
        # Diagnostics are best effort; the original refusal always wins.
        pass
    raise GuestError('Guest console after WAN probe failed at ' + probe['phase'] + ': ' + probe['failure'])
