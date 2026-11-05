"""Capture one consistent protected-host point inside the owned source guest.

Only the fixed guest layout is eligible. Dumps, metadata and payloads remain
private; stopping and reaping the original guest belongs to the outer driver.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

from database import capture, snapshot_fingerprint
from host_layout import (COMPOSE, DEPLOYMENT, HELPER, PROJECT, RUNNING, SERVICE_ROLES,
                         STATE_ROOTS, TRANSFER, UNITS, VOLUMES, WRITERS, valid_tags)
from payload import pack, private_info


class CheckpointError(Exception):
    """Messages identify only fixed operations, not private child diagnostics."""


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private_json(path, maximum=4 * 1024**2, *, owners=(0,)):
    path = Path(path)
    info = path.lstat()
    if (path != path.resolve(strict=True) or not stat.S_ISREG(info.st_mode)
            or info.st_uid not in owners or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
            or not 0 < info.st_size <= maximum):
        raise CheckpointError('Private checkpoint JSON file refused')
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise CheckpointError('Private checkpoint JSON identity changed')
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise CheckpointError('Private checkpoint JSON size refused')
    return json.loads(raw)


def valid_capture_input(value):
    keys = {'version', 'machine_id', 'boot_id', 'source_head', 'tags', 'unit_hashes',
            'account_hash', 'native_device_id', 'pending_request_id'}
    try:
        return (isinstance(value, dict) and set(value) == keys and type(value['version']) is int
                and value['version'] == 1 and re.fullmatch('[a-f0-9]{32}', value['machine_id']) is not None
                and str(uuid.UUID(value['boot_id'])) == value['boot_id']
                and re.fullmatch('[a-f0-9]{40}', value['source_head']) is not None
                and valid_tags(value['tags']) and set(value['unit_hashes']) == set(UNITS)
                and all(re.fullmatch('[a-f0-9]{64}', h) is not None for h in value['unit_hashes'].values())
                and re.fullmatch('[a-f0-9]{64}', value['account_hash']) is not None
                and all(str(uuid.UUID(value[k])) == value[k] for k in ('native_device_id', 'pending_request_id')))
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


class SourceCheckpoint:
    def __init__(self, expected):
        root = Path(TRANSFER)
        if (sys.platform != 'linux' or os.geteuid() != 0 or Path(__file__).resolve().parent != root
                or not valid_capture_input(expected)):
            raise CheckpointError('Owned source guest checkpoint required')
        info = root.lstat()
        if (root != root.resolve(strict=True) or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700
                or Path('/etc/machine-id').read_text().strip() != expected['machine_id']
                or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != expected['boot_id']):
            raise CheckpointError('Owned source guest identity differs')
        self.expected = expected
        self.work = root / 'checkpoint-private'
        self.work.mkdir(mode=0o700)
        self.counter = 0

    def command(self, arguments, label, *, timeout=60):
        self.counter += 1
        try:
            result = subprocess.run(arguments, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise CheckpointError(label + ' unavailable or timed out') from None
        (self.work / f'step-{self.counter}.log').write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise CheckpointError(label + ' failed')
        return result.stdout

    def property(self, unit, name):
        return self.command(['systemctl', 'show', unit, '--property=' + name, '--value'],
                            'Source persistent unit observation').decode().strip()

    def inventory(self):
        ids = self.command([*COMPOSE, 'ps', '-q'], 'Source service inventory').decode().splitlines()
        if len(ids) != 6 or any(re.fullmatch('[a-f0-9]{64}', value) is None for value in ids):
            raise CheckpointError('Exactly six original source services required')
        services = {}
        for value in json.loads(self.command(['docker', 'inspect', *ids], 'Source service ownership')):
            labels = value['Config']['Labels']
            name = labels.get('com.docker.compose.service')
            if (labels.get('com.docker.compose.project') != PROJECT or name not in RUNNING
                    or name in services or value['State']['Running'] is not True
                    or value['Config']['Image'] != self.expected['tags'][SERVICE_ROLES[name]]):
                raise CheckpointError('Original source service binding differs')
            services[name] = value
        if set(services) != RUNNING:
            raise CheckpointError('Original source service set differs')
        for name, mountpoint in VOLUMES.items():
            mounts = [m for v in services.values() for m in v['Mounts']
                      if m['Type'] == 'volume' and m['Name'] == PROJECT + '_' + name]
            volume = json.loads(self.command(['docker', 'volume', 'inspect', PROJECT + '_' + name],
                                             'Source persistent volume identity'))
            if (len(mounts) != 1 or len(volume) != 1 or mounts[0]['Source'] != mountpoint
                    or volume[0]['Mountpoint'] != mountpoint
                    or volume[0]['Labels'].get('com.docker.compose.project') != PROJECT
                    or volume[0]['Labels'].get('com.docker.compose.volume') != name):
                raise CheckpointError('Original source persistent volume differs')
        mounts = services['caddy']['Mounts']
        binds = {m['Destination']: (m['Source'], m['RW']) for m in mounts if m['Type'] == 'bind'}
        if len(mounts) != 4 or binds != {'/etc/caddy/Caddyfile': (DEPLOYMENT + '/Caddyfile', False),
                                       '/nethub-http01': ('/srv/nethub-http01', False)}:
            raise CheckpointError('Original public-only proxy mounts differ')
        self.services, self.postgres = services, services['postgres']['Id']

    def sql(self, query):
        return self.command(['docker', 'exec', '-i', self.postgres, 'psql', '-X', '-qAt',
                             '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'nethub', '-c', query],
                            'Source consistent database read').decode().strip()

    def unit_intent(self):
        intent = {}
        for unit in UNITS:
            path = Path('/etc/systemd/system') / unit
            info = private_info(path)
            if (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o644
                    or digest(path) != self.expected['unit_hashes'][unit]
                    or self.property(unit, 'FragmentPath') != str(path)
                    or self.property(unit, 'DropInPaths') != '' or self.property(unit, 'LoadState') != 'loaded'):
                raise CheckpointError('Original stock persistent issuer unit differs')
            state = self.property(unit, 'UnitFileState')
            if state != ('enabled' if unit.endswith('.timer') else 'static'):
                raise CheckpointError('Original protected timer enabled intent differs')
            intent[unit] = state
        return intent

    @contextmanager
    def lease(self):
        import fcntl

        path = Path(DEPLOYMENT) / 'relay-operation.lock'
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'r+b') as lock:
            info = os.fstat(lock.fileno())
            actual = path.lstat()
            if (path != path.resolve(strict=True) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_nlink != 1 or info.st_size != 0 or stat.S_IMODE(info.st_mode) != 0o600
                    or (info.st_dev, info.st_ino) != (actual.st_dev, actual.st_ino)):
                raise CheckpointError('Original protected operation lease refused')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def capture(self):
        self.inventory()
        self.command([HELPER, 'doctor', '--directory', DEPLOYMENT, '--runtime-containers', '--project', PROJECT],
                     'Source current keys backup and runtime separation')
        intent = self.unit_intent()
        if (self.property('nethub-http01-cleanup.service', 'Result') != 'success'
                or self.property('nethub-http01-cleanup.service', 'ExecMainStatus') != '0'):
            raise CheckpointError('Original independent cleanup success required')
        if digest('/var/lib/nethub-gui-acme/account.json') != self.expected['account_hash']:
            raise CheckpointError('Original registered account identity differs')
        with self.lease():
            self.command(['systemctl', 'stop', *UNITS], 'Source issuer writer quiescence', timeout=60)
            if any(self.property(unit, 'ActiveState') != 'inactive' for unit in UNITS):
                raise CheckpointError('Original issuer workers remain active')
            self.command([*COMPOSE, 'stop', '--timeout', '10', *WRITERS], 'Source application writer quiescence', timeout=75)
            database = capture(self.sql)
            system = self.sql('SELECT system_identifier FROM pg_control_system();')
            device, request = self.expected['native_device_id'], self.expected['pending_request_id']
            pending = ("SELECT count(*) FROM gui_certificate_jobs WHERE device_id='" + device + "' AND request_id='" + request
                       + "' AND generation=1 AND state='queued' AND failures=0 AND recoveries=0 AND polls=0 "
                       "AND lease_token IS NULL AND deadline>clock_timestamp();")
            if (self.sql(pending) != '1' or self.sql("SELECT count(*) FROM gui_certificate_generations WHERE request_id='" + request + "';") != '0'):
                raise CheckpointError('Genuine initial native issuance job must remain pending')
            self.command([*COMPOSE, 'run', '--rm', '--no-deps', '-T', 'backup', 'backup', 'run',
                          '--sslmode', 'disable', '--timeout', '60s', '--max-bytes', str(64 * 1024**2)],
                         'Source restricted full database archive', timeout=90)
            state = private_json(Path(VOLUMES['database-backups']) / 'last-run.json', owners=(65532,))
            receipt = state['latest_success']
            if (state['outcome'] != 'succeeded' or receipt['role'] != 'nethub_backup'
                    or re.fullmatch(r'nethub-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}\.dump', receipt['archive']) is None):
                raise CheckpointError('Source restricted backup receipt differs')
            dump = Path(VOLUMES['database-backups']) / receipt['archive']
            info = private_info(dump)
            if digest(dump) != receipt['sha256'] or info.st_size != receipt['bytes']:
                raise CheckpointError('Source database archive integrity differs')
            if snapshot_fingerprint(capture(self.sql)) != snapshot_fingerprint(database):
                raise CheckpointError('Source database changed during the consistent checkpoint')
            self.command([*COMPOSE, 'stop', '--timeout', '10', 'postgres'], 'Original database shutdown', timeout=30)
            if self.command([*COMPOSE, 'ps', '-q'], 'Stopped original service inventory').strip():
                raise CheckpointError('Original source services remain running')
            paths = set()
            for name in STATE_ROOTS:
                root = Path(name)
                private_info(root)
                paths.add(root)
                if root.is_dir():
                    paths.update(root.rglob('*'))
            payload = Path(TRANSFER) / 'current-files.tar'
            integrity = pack(paths, payload)
            metadata = {'version': 1, 'source_head': self.expected['source_head'],
                        'source_machine_id': self.expected['machine_id'], 'source_boot_id': self.expected['boot_id'],
                        'tags': self.expected['tags'], 'original_service_ids': {n: v['Id'] for n, v in self.services.items()},
                        'roots': list(STATE_ROOTS), 'unit_hashes': self.expected['unit_hashes'], 'unit_intent': intent,
                        'account_hash': self.expected['account_hash'], 'native_device_id': device, 'pending_request_id': request,
                        'database': database, 'database_fingerprint': snapshot_fingerprint(database),
                        'original_database_system': system, 'dump': str(dump), 'dump_sha256': receipt['sha256'],
                        'payload': integrity, 'original_services_and_issuer_stopped': True}
            with (Path(TRANSFER) / 'checkpoint.json').open('x', encoding='utf-8') as output:
                json.dump(metadata, output, separators=(',', ':'))
                output.write('\n')
                output.flush()
                os.fsync(output.fileno())
            return {'consistent_private_checkpoint_created': True,
                    'original_services_and_issuer_stopped': True, 'same_pending_native_job_retained': True,
                    'source_guest_poweroff_verified': False, 'full_host_recovery_accepted': False}


if __name__ == '__main__':
    os.umask(0o077)
    try:
        if sys.argv[1:] != ['capture']:
            raise CheckpointError('Owned checkpoint action required')
        print(json.dumps(SourceCheckpoint(private_json(Path(TRANSFER) / 'capture-input.json', 65536)).capture()))
    except Exception:
        raise SystemExit('Private source checkpoint failed; inspect owned guest logs') from None
