"""Read closed package/runtime fingerprints on the nonce-bound disposable guest."""
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET

from wan_probe import ProbeError, boundary, controls


MARKERS = ('disabled', 'stopped', 'revoked', 'uninstalling', 'rotation.json', 'recovery.json', 'rollback-attempt')
HASHES = ('model_values_sha256', 'runtime_identity_sha256', 'gui_identity_sha256', 'relay_ca_sha256', 'frpc_sha256')
FIELDS = set(HASHES) | {'version', 'package_version', 'profile', 'markers', 'running', 'pid',
                       'process_sha256', 'control_sha256'}
PHASE = 'native_package_probe'
BOUNDARY_PHASES = ('host', 'nonce', 'marker', 'interfaces', 'lan', 'route', 'wan')
ROUTE_FAILURES = ('wan_route_table', 'wan_route_missing', 'wan_route_mismatch')


def boundary_phase(name):
    global PHASE
    if name not in BOUNDARY_PHASES:
        raise ValueError('Unexpected native package boundary checkpoint')
    PHASE = 'native_package_boundary_' + name


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def canonical(node):
    if node is None:
        raise ValueError('Required native configuration node is absent')
    return [node.tag, sorted(node.attrib.items()), (node.text or '') if not len(node) else '',
            [canonical(child) for child in node]]


def validate(value):
    if (not isinstance(value, dict) or set(value) != FIELDS or type(value['version']) is not int
            or value['version'] != 1 or value['package_version'] not in ('0.0.18', '0.0.19')
            or not isinstance(value['profile'], list) or len(value['profile']) != 2
            or any(type(number) is not int for number in value['profile'])
            or value['profile'] not in ([10, 30], [1, 3])
            or not isinstance(value['markers'], dict) or set(value['markers']) != set(MARKERS)
            or any(type(flag) is not bool for flag in value['markers'].values())
            or type(value['running']) is not bool or type(value['pid']) is not int
            or not 0 <= value['pid'] < 2**31):
        raise ValueError('Unexpected native package observation')
    for key in HASHES:
        if not isinstance(value[key], str) or not re.fullmatch('[a-f0-9]{64}', value[key]):
            raise ValueError('Unexpected native package fingerprint')
    for key in ('process_sha256', 'control_sha256'):
        if value[key] is not None and (not isinstance(value[key], str) or not re.fullmatch('[a-f0-9]{64}', value[key])):
            raise ValueError('Unexpected native package process/control fingerprint')
    if value['running'] != (value['pid'] > 0 and value['process_sha256'] is not None):
        raise ValueError('Inconsistent native package process state')
    if not value['running'] and (value['pid'] != 0 or value['process_sha256'] is not None or value['control_sha256'] is not None):
        raise ValueError('A stopped native client cannot retain a control')


def run(arguments):
    result = subprocess.run(arguments, capture_output=True, timeout=20)
    if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 16384:
        raise ValueError('Owned package inspection failed')
    return result.stdout.decode('utf-8')


def inspect():
    global PHASE
    PHASE = 'native_package_model'
    root = ET.parse('/conf/config.xml').getroot()
    model = root.find('OPNsense/NetHubAgent')
    if model is None or any(len(child) for child in model):
        raise ValueError('Expected a flat native agent model')
    nodes = {child.tag: child.text or '' for child in model}
    if len(nodes) != len(model) or nodes.get('enabled') != '1':
        raise ValueError('Enabled native enrollment required')
    PHASE = 'native_package_gui'
    gui = root.find('system/webgui')
    reference = gui.findtext('ssl-certref') if gui is not None else None
    certificates = [entry for entry in root.findall('cert') if entry.findtext('refid') == reference]
    if gui is None or len(certificates) != 1 or gui.find('nodnsrebindcheck') is not None or gui.find('nohttpreferercheck') is not None:
        raise ValueError('Original GUI identity and security checks required')
    PHASE = 'native_package_runtime'
    value = tomllib.loads(Path('/usr/local/etc/nethub-agent/frpc.toml').read_text())
    transport = value.get('transport', {})
    if not isinstance(transport, dict):
        raise ValueError('Native transport must be a table')
    profile = [transport.pop('heartbeatInterval'), transport.pop('heartbeatTimeout')]
    if value.get('loginFailExit') is not False or transport.get('tls', {}).get('enable') is not True:
        raise ValueError('Retrying verified native TLS required')
    PHASE = 'native_package_markers'
    state = Path('/var/db/nethub-agent')
    markers = {}
    for name in MARKERS:
        path = state / name
        if path.is_symlink():
            raise ValueError('Aliased lifecycle marker refused')
        markers[name] = path.exists()
    PHASE = 'native_package_manifest'
    package = run(['/usr/local/sbin/pkg', 'query', '%v', 'os-nethub-agent']).strip()
    run(['/usr/local/sbin/pkg', 'check', '-s', 'os-nethub-agent'])
    PHASE = 'native_package_process'
    pid, process, control = 0, None, None
    pidfile = Path('/var/run/nethub_agent_frpc.pid')
    if pidfile.exists():
        raw_pid = pidfile.read_text().strip()
        if not re.fullmatch('[1-9][0-9]{0,9}', raw_pid):
            raise ValueError('Unexpected native PID file')
        found = subprocess.run(['/bin/ps', '-o', 'comm=', '-p', raw_pid], capture_output=True, timeout=5)
        if found.returncode == 0 and found.stdout.strip() == b'frpc':
            pid = int(raw_pid)
            started = run(['/bin/ps', '-o', 'lstart=', '-p', raw_pid]).strip()
            if not started or len(started) > 128:
                raise ValueError('Native process start identity unavailable')
            process = fingerprint([pid, started])
            raw = run(['/usr/bin/sockstat', '-4', '-c', '-n', '-s', '-P', 'tcp', '-p', '7000'])
            if controls(raw, pid):
                rows = [line.split() for line in raw.splitlines()[1:] if len(line.split()) == 8
                        and line.split()[2] == raw_pid and line.split()[-1] == 'ESTABLISHED']
                control = fingerprint(rows)
    PHASE = 'native_package_files'
    ca = Path('/usr/local/etc/nethub-agent/relay-ca.pem')
    binary = Path('/usr/local/opnsense/nethub-agent/bin/frpc')
    for path in (ca, binary):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.is_symlink():
            raise ValueError('Regular native runtime files required')
    with binary.open('rb') as source:
        binary_hash = hashlib.file_digest(source, 'sha256').hexdigest()
    result = {'version': 1, 'package_version': package, 'profile': profile, 'markers': markers,
        'running': pid > 0, 'pid': pid, 'process_sha256': process, 'control_sha256': control,
        'model_values_sha256': fingerprint(nodes), 'runtime_identity_sha256': fingerprint(value),
        'gui_identity_sha256': fingerprint([canonical(gui), canonical(certificates[0])]),
        'relay_ca_sha256': hashlib.sha256(ca.read_bytes()).hexdigest(), 'frpc_sha256': binary_hash}
    PHASE = 'native_package_validation'
    validate(result)
    return result


def main(arguments):
    global PHASE
    PHASE = 'native_package_probe'
    try:
        if len(arguments) != 1:
            raise ValueError('Owned package nonce required')
        PHASE = 'native_package_boundary'
        boundary(arguments[0], observe=boundary_phase)
        print(json.dumps(inspect(), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, ET.ParseError) as error:
        # Preserve only the route verifier's closed codes, never its input or
        # command output. A failed boundary still stops before inspection.
        if (PHASE == 'native_package_boundary_route' and isinstance(error, ProbeError)
                and str(error) in ROUTE_FAILURES):
            PHASE += '_' + str(error).removeprefix('wan_route_')
        print(json.dumps({'success': False, 'fixture_phase': PHASE}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
