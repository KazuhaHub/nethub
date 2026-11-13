"""Change only the fixed WAN address of a nonce-bound disposable CI guest."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET


ADDRESSES = ('10.0.2.15', '10.0.2.16')
HEADER = 'USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS PATH STATE CONN STATE'.split()
TCP_HEADER = 'USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS CONN STATE'.split()


class ProbeError(ValueError):
    """An allowlisted diagnostic without command output or configuration."""


def gateway(*, allow_missing=False, repair=False):
    lines = run(['/usr/bin/netstat', '-rn', '-f', 'inet']).splitlines()
    if sum(line.split() == ['Destination', 'Gateway', 'Flags', 'Netif', 'Expire']
           for line in lines) != 1:
        raise ProbeError('wan_route_table')
    rows = [line.split() for line in lines if line.split()[:1] == ['default']]
    if not rows:
        if repair:
            run(['/sbin/route', '-n', 'add', 'default', '10.0.2.2'])
            gateway()
            return
        if allow_missing:
            return
        raise ProbeError('wan_route_missing')
    if (len(rows) != 1 or len(rows[0]) != 4 or rows[0][1] != '10.0.2.2'
            or rows[0][3] != 'em1'):
        raise ProbeError('wan_route_mismatch')
    route = run(['/sbin/route', '-n', 'get', 'default'])
    if (re.findall(r'^\s*gateway:\s*(\S+)\s*$', route, re.M) != ['10.0.2.2']
            or re.findall(r'^\s*interface:\s*(\S+)\s*$', route, re.M) != ['em1']):
        raise ProbeError('wan_route_mismatch')


def run(arguments):
    result = subprocess.run(arguments, capture_output=True, timeout=5)
    if result.returncode or len(result.stdout) > 1024 * 1024:
        raise ValueError('Owned WAN probe command unavailable')
    return result.stdout.decode('utf-8')


def address(raw, interface, allowed):
    lines = raw.splitlines()
    if not lines or not lines[0].startswith(interface + ':'):
        raise ValueError('Unexpected owned interface')
    rows = [line.split() for line in lines if line.strip().startswith('inet ')]
    if (len(rows) != 1 or len(rows[0]) != 6 or rows[0][0] != 'inet'
            or rows[0][1] not in allowed or rows[0][2:4] != ['netmask', '0xffffff00']
            or rows[0][4] != 'broadcast' or rows[0][5] != rows[0][1].rsplit('.', 1)[0] + '.255'):
        raise ValueError('Unexpected owned IPv4 address')
    return rows[0][1]


def controls(raw, pid):
    lines = raw.splitlines()
    if not lines or lines[0].split() not in (HEADER, TCP_HEADER):
        raise ValueError('Unexpected owned socket table')
    found = []
    for line in lines[1:]:
        row = line.split()
        if len(row) < 3 or row[2] != str(pid):
            continue
        if (len(row) != 8 or row[:3] != ['0', 'frpc', str(pid)] or not row[3].isdecimal()
                or row[4] != 'tcp4' or row[6] != '10.0.2.100:7000'
                or re.fullmatch(r'10\.0\.2\.(?:15|16):[1-9][0-9]{0,4}', row[5]) is None):
            raise ValueError('Unexpected original frpc socket')
        host, port = row[5].rsplit(':', 1)
        if not 1 <= int(port) <= 65535:
            raise ValueError('Unexpected original frpc port')
        if row[7] == 'ESTABLISHED':
            found.append(host)
    if len(found) > 1:
        raise ValueError('Ambiguous original frpc control')
    return found


def boundary(nonce, *, require_route=True):
    if os.name != 'posix' or os.uname().sysname != 'FreeBSD' or os.geteuid() != 0:
        raise ValueError('Owned FreeBSD root fixture required')
    if re.fullmatch('[a-f0-9]{32}', nonce) is None:
        raise ValueError('Owned nonce required')
    marker = Path('/root/nethub-ci/native-fixture-nonce')
    info = marker.lstat()
    if (marker.resolve(strict=True) != marker or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 64 or not Path('/root/nethub-ci/sshd.conf').is_file()
            or not hmac.compare_digest(marker.read_text().strip(), nonce)):
        raise ValueError('Owned guest nonce binding refused')
    root = ET.parse('/conf/config.xml').getroot()
    if root.findtext('interfaces/lan/if') != 'em0' or root.findtext('interfaces/wan/if') != 'em1':
        raise ValueError('Owned LAN and WAN binding changed')
    address(run(['/sbin/ifconfig', 'em0', 'inet']), 'em0', ('192.168.1.1',))
    gateway(allow_missing=not require_route)
    return address(run(['/sbin/ifconfig', 'em1', 'inet']), 'em1', ADDRESSES)


def inspect():
    current = address(run(['/sbin/ifconfig', 'em1', 'inet']), 'em1', ADDRESSES)
    pid = Path('/var/run/nethub_agent_frpc.pid').read_text().strip()
    if re.fullmatch('[1-9][0-9]{0,9}', pid) is None:
        raise ValueError('Original frpc PID unavailable')
    if run(['/bin/ps', '-o', 'comm=', '-p', pid]).strip() != 'frpc':
        raise ValueError('Original frpc executable changed')
    started = run(['/bin/ps', '-o', 'lstart=', '-p', pid]).strip()
    if not started or len(started) > 128:
        raise ValueError('Original frpc start unavailable')
    peers = controls(run(['/usr/bin/sockstat', '-4', '-c', '-n', '-s', '-P', 'tcp', '-p', '7000']), int(pid))
    return {'address': current, 'pid': int(pid), 'started': started, 'control_sources': peers,
            'runtime_sha256': hashlib.sha256(Path('/usr/local/etc/nethub-agent/frpc.toml').read_bytes()).hexdigest(),
            'native_xml_sha256': hashlib.sha256(Path('/conf/config.xml').read_bytes()).hexdigest()}


def operation(action, nonce):
    if action not in ('inspect', 'change', 'restore'):
        raise ValueError('Unknown owned WAN operation')
    current = boundary(nonce, require_route=action != 'restore')
    if action == 'change':
        if current != ADDRESSES[0]:
            raise ValueError('Original WAN baseline required')
        inspect()
        run(['/sbin/ifconfig', 'em1', 'inet', ADDRESSES[1], 'netmask', '255.255.255.0'])
        # Replacing a primary address may remove its dependent routes. Repair
        # only the fixed fixture gateway; never replace an unexpected route.
        gateway(repair=True)
    elif action == 'restore':
        if current != ADDRESSES[0]:
            run(['/sbin/ifconfig', 'em1', 'inet', ADDRESSES[0], 'netmask', '255.255.255.0'])
        gateway(repair=True)
        return {'restored': boundary(nonce) == ADDRESSES[0]}
    return inspect()


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3:
            raise ValueError('Owned WAN arguments required')
        print(json.dumps(operation(*sys.argv[1:])))
    except (OSError, ValueError, subprocess.SubprocessError, ET.ParseError) as error:
        reason = str(error) if isinstance(error, ProbeError) else 'wan_probe'
        print(json.dumps({'success': False, 'fixture_phase': reason}))
        raise SystemExit(1)
