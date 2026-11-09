"""Privately inspect the genuine enrolled key/CSR without creating either.

This disposable-guest probe returns public CSR bytes and private fixture identity
metadata. Capture its output privately; it is never an uploadable receipt. It does
not change the native model, create a key/request, restart a service or report a
certificate application on behalf of the agent.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET


def decode_request(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('Duplicate private probe input')
            value[key] = item
        return value

    if not isinstance(raw, bytes) or len(raw) > 4096:
        raise ValueError('Private probe input size refused')
    value = json.loads(raw, object_pairs_hook=pairs)
    if (not isinstance(value, dict) or set(value) != {'nonce', 'device_id', 'host'}
            or not isinstance(value['nonce'], str) or re.fullmatch('[a-f0-9]{32}', value['nonce']) is None
            or not isinstance(value['device_id'], str) or str(uuid.UUID(value['device_id'])) != value['device_id']
            or not isinstance(value['host'], str)
            or re.fullmatch(r'[a-z0-9]{8}\.devices\.example\.test', value['host']) is None):
        raise ValueError('Private native probe binding refused')
    return value


def protected(path, *, directory=False, maximum=8192):
    info = path.lstat()
    if (path != path.resolve(strict=True) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or not directory and (info.st_nlink != 1 or info.st_size > maximum)):
        raise ValueError('Private native probe file refused')
    return info


def run(arguments, data=None):
    result = subprocess.run(arguments, input=data, capture_output=True, timeout=5)
    if result.returncode or len(result.stdout) > 16384 or len(result.stderr) > 8192:
        raise ValueError('Private native observation failed')
    return result.stdout


def inspect(request):
    if (not sys.platform.startswith('freebsd') or os.geteuid() != 0
            or Path(__file__).resolve().parent != Path('/root/nethub-ci')):
        raise ValueError('Owned disposable FreeBSD guest required')
    import fcntl

    directory = Path('/root/nethub-ci')
    protected(directory, directory=True)
    marker = directory / 'native-fixture-nonce'
    protected(marker, maximum=33)
    protected(directory / 'sshd.conf')
    if marker.read_text().strip() != request['nonce']:
        raise ValueError('Owned native fixture identity differs')
    state = Path('/var/db/nethub-agent')
    protected(state, directory=True)
    lock = state / 'reconcile.lock'
    original = protected(lock, maximum=0)
    descriptor = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (original.st_dev, original.st_ino):
            raise ValueError('Native mutation lock changed')
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        sys.path.insert(0, '/usr/local/opnsense/scripts/nethub-agent')
        from agentctl import Agent
        from certificate_key import KeyStore
        from certificate_request import RequestStore
        from rotation_backend import NativeRotationBackend, assignment

        agent = Agent()
        native = NativeRotationBackend().read()
        assigned = assignment(native)
        if (native['enabled'] != '1' or native['console_url'] != 'https://console.example.com'
                or assigned['device_id'] != request['device_id']
                or assigned['subdomain'] != request['host'].split('.')[0] or not agent.running()):
            raise ValueError('Original running native assignment differs')
        keys = KeyStore(agent.config / 'gui-key')
        key = keys._load()
        requests = RequestStore(agent.config / 'gui-request', keys)
        keys._protected(requests.directory, directory=True)
        path = requests.directory / 'request.json'
        info = keys._protected(path)
        if not 128 <= info.st_size <= 8192 or {p.name for p in requests.directory.iterdir()} != {'request.json'}:
            raise ValueError('Original persisted native request unavailable')
        raw = path.read_bytes()
        value = json.loads(raw)
        if requests._encoded(value) != raw:
            raise ValueError('Original native request encoding differs')
        csr = requests._validate(value, request['host'], key)
        root = ET.parse('/conf/config.xml').getroot()
        gui = root.find('system/webgui')
        if gui is None or gui.find('nodnsrebindcheck') is not None or gui.find('nohttpreferercheck') is not None:
            raise ValueError('Original native security checks changed')
        reference = gui.findtext('ssl-certref')
        entries = [entry for entry in root.findall('cert') if entry.findtext('refid') == reference]
        if not reference or len(entries) != 1:
            raise ValueError('Original native GUI certificate selection ambiguous')
        leaf = base64.b64decode(entries[0].findtext('crt'), validate=True)
        public = run(['/usr/bin/openssl', 'x509', '-pubkey', '-noout'], leaf)
        native_public = run(['/usr/bin/openssl', 'pkey', '-pubin', '-outform', 'DER'], public)
        leaf_der = run(['/usr/bin/openssl', 'x509', '-outform', 'DER'], leaf)
        pid = Path('/var/run/nethub_agent_frpc.pid').read_text().strip()
        if re.fullmatch('[1-9][0-9]{0,9}', pid) is None:
            raise ValueError('Original frpc process identity unavailable')
        started = run(['/bin/ps', '-o', 'lstart=', '-p', pid]).decode().strip()
        if not started or len(started) > 128:
            raise ValueError('Original frpc process start unavailable')
        native_fingerprint = hashlib.sha256(native_public).hexdigest()
        transaction = agent.gui_transaction()
        journal = transaction._read()
        applied = None
        confirmed = False
        if journal is not None:
            applied = {key: journal[key] for key in ('phase', 'device_id', 'generation_id', 'generation', 'refid')}
            if journal['phase'] == 'applied':
                confirmed = transaction.backend.check(journal) is True and transaction.backend.probe(journal) is True
        return {'version': 1, 'device_id': request['device_id'], 'host': request['host'],
                'enrollment_gui_key_fingerprint': key['fingerprint'],
                'native_active_gui_key_fingerprint': native_fingerprint,
                'native_GUI_already_uses_enrollment_key': native_fingerprint == key['fingerprint'],
                'original_cached_csr_pem': csr.decode('ascii'),
                'original_cached_csr_sha256': hashlib.sha256(base64.b64decode(value['csr'], validate=True)).hexdigest(),
                'native_leaf_fingerprint': hashlib.sha256(leaf_der).hexdigest(), 'native_certref': reference,
                'native_security_checks_enabled': True,
                'native_alternate_present': request['host'] in gui.findtext('althostnames', '').split(),
                'frpc_pid': int(pid), 'frpc_started': started,
                'native_apply': applied, 'native_applied_selection_and_verified_loopback_TLS_confirmed': confirmed,
                'private_assignment_fingerprint': hashlib.sha256(json.dumps(native, sort_keys=True).encode()).hexdigest(),
                'certificate_application_or_full_recovery_accepted': False}


if __name__ == '__main__':
    try:
        if sys.argv[1:]:
            raise ValueError('Private probe takes only stdin')
        print(json.dumps(inspect(decode_request(sys.stdin.buffer.read(4097)))))
    except BlockingIOError:
        print(json.dumps({'available': False, 'reason': 'mutation_busy'}))
    except Exception:
        raise SystemExit('Private cold native probe refused') from None
