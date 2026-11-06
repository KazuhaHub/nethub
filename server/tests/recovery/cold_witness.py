"""Keep the isolated ACME witness outside both recovery guests.

The nonce-owned systemd service contains the test process and its children. An
independent timer removes only its labelled CA container/network if the driver
exits. Private logs, account keys and control files are never public artifacts.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time


IMAGE = 'ghcr.io/letsencrypt/pebble@sha256:5080492187bea12909c053d7a2b90a9e95104ef1c82381828e7823db71ce7e54'
ENVIRONMENT = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'HOME': '/root', 'LANG': 'C', 'LC_ALL': 'C',
               'DOCKER_HOST': 'unix:///var/run/docker.sock'}


class WitnessError(Exception):
    """Only fixed operation labels may leave this private driver."""


def unit_names(nonce):
    if not isinstance(nonce, str) or re.fullmatch('[a-f0-9]{16}', nonce) is None:
        raise WitnessError('Private witness identity refused')
    return 'nethub-cold-witness-' + nonce, 'nethub-cold-witness-guard-' + nonce


def private_json(path):
    info = path.lstat()
    if (path != path.resolve(strict=True) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
            or not 0 < info.st_size <= 4096):
        raise WitnessError('Private witness control file refused')
    return json.loads(path.read_bytes())


def write_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
        json.dump(value, output)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def owned_control(control):
    if (sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise WitnessError('Fresh root Linux hosted witness required')
    parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    if (control != control.resolve(strict=True) or control.parent != parent
            or re.fullmatch('nethub-cold-witness-[a-f0-9]{16}', control.name) is None):
        raise WitnessError('Owned witness control namespace refused')
    info = control.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise WitnessError('Private witness control ownership refused')
    return control.name.removeprefix('nethub-cold-witness-')


def command(control, args, *, timeout=30, check=True):
    if args[0] == 'docker':
        args = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', *args[1:]]
    try:
        result = subprocess.run(args, env=ENVIRONMENT, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise WitnessError('Owned witness operation unavailable or timed out') from None
    descriptor = os.open(control / 'commands-private.log', os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'ab') as output:
        output.write(result.stdout + result.stderr)
    if check and result.returncode:
        raise WitnessError('Owned witness operation failed; private log retained')
    return result


def property_value(control, unit, prop):
    return command(control, ['/usr/bin/systemctl', 'show', unit, '--property=' + prop, '--value']).stdout.decode().strip()


def inspect(control, kind, name):
    result = command(control, ['docker', kind, 'inspect', name], check=False)
    if result.returncode:
        command(control, ['docker', 'info', '--format', '{{.ID}}'])
        if b'no such' not in result.stderr.lower() and b'not found' not in result.stderr.lower():
            raise WitnessError('Witness resource absence not established')
        return None
    values = json.loads(result.stdout)
    if len(values) != 1:
        raise WitnessError('Witness resource identity refused')
    return values[0]


def valid_state(value, nonce):
    return (isinstance(value, dict) and set(value) == {'version', 'nonce', 'image_id', 'binary_sha256'}
            and type(value['version']) is int and value['version'] == 1 and value['nonce'] == nonce
            and isinstance(value['image_id'], str) and re.fullmatch('sha256:[a-f0-9]{64}', value['image_id']) is not None
            and isinstance(value['binary_sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['binary_sha256']) is not None)


def owned_resource(value, kind, nonce, image):
    try:
        if (kind not in ('container', 'network') or not isinstance(value, dict)
                or re.fullmatch('[a-f0-9]{64}', value['Id']) is None):
            return False
        labels = value['Config']['Labels'] if kind == 'container' else value['Labels']
        if labels.get('org.nethub.guiacme-test') != nonce:
            return False
        if kind == 'network':
            return value['Internal'] is True and value['Driver'] == 'bridge' and value['Containers'] == {}
        return (value['Image'] == image and value['HostConfig']['ReadonlyRootfs'] is True
                and not value['HostConfig'].get('PortBindings'))
    except (KeyError, TypeError, AttributeError):
        return False


def cleanup(control):
    import fcntl

    nonce = owned_control(control)
    service, _ = unit_names(nonce)
    descriptor = os.open(control / 'cleanup.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        if (info.st_uid != 0 or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0):
            raise WitnessError('Private witness cleanup lease refused')
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = private_json(control / 'state.json')
        if not valid_state(state, nonce):
            raise WitnessError('Owned witness cleanup state refused')
        unit = service + '.service'
        loaded = property_value(control, unit, 'LoadState')
        if loaded != 'not-found':
            if property_value(control, unit, 'Description') != 'NetHub isolated cold witness ' + nonce:
                raise WitnessError('Witness unit ownership changed; preserved')
            command(control, ['/usr/bin/systemctl', 'stop', unit], timeout=40)
            if property_value(control, unit, 'ActiveState') not in ('inactive', 'failed'):
                raise WitnessError('Owned witness process group still active')
        for kind, name in (('container', 'nethub-acme-test-' + nonce),
                           ('network', 'nethub-acme-test-' + nonce + '-network')):
            value = inspect(control, kind, name)
            if value is None:
                continue
            if not owned_resource(value, kind, nonce, state['image_id']):
                raise WitnessError('Witness resource ownership or binding changed; preserved')
            command(control, ['docker', kind, 'rm', *(['--force'] if kind == 'container' else []), value['Id']])
            if inspect(control, kind, name) is not None:
                raise WitnessError('Owned witness resource remains')
        temporary = control / 'tmp'
        if temporary.exists() or temporary.is_symlink():
            if (temporary != temporary.resolve(strict=True) or not temporary.is_dir()
                    or temporary.stat().st_uid != 0 or temporary.parent != control):
                raise WitnessError('Witness temporary key namespace changed; preserved')
            shutil.rmtree(temporary)
        if not (control / 'cleanup.json').exists():
            write_json(control / 'cleanup.json', {'owned_CA_and_process_group_removed': True,
                                                'temporary_witness_keys_removed': True,
                                                'full_host_recovery_accepted': False})


class ColdWitness:
    def __init__(self, binary, assigned_host, forward_port, *, ownership_record=None):
        # The full driver's exact-source build/image producer gate is separate.
        self.binary, self.host, self.forward_port = Path(binary), assigned_host, forward_port
        self.ownership_record = None if ownership_record is None else Path(ownership_record)
        self.control = None

    def __enter__(self):
        if (sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
                or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
                or re.fullmatch(r'[a-z0-9]{8}\.devices\.example\.test', self.host) is None
                or type(self.forward_port) is not int or not 1024 <= self.forward_port <= 65535):
            raise WitnessError('Owned hosted witness request refused')
        info = self.binary.lstat()
        if (self.binary != self.binary.resolve(strict=True) or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1 or info.st_mode & 0o022 or not 0 < info.st_size <= 64 * 1024**2):
            raise WitnessError('Exact built witness executable refused')
        nonce = secrets.token_hex(8)
        self.service, self.guard = unit_names(nonce)
        self.control = Path(os.environ['RUNNER_TEMP']).resolve(strict=True) / self.service
        self.control.mkdir(mode=0o700)
        owned_control(self.control)
        try:
            if self.ownership_record is not None:
                owner = self.ownership_record.parent
                info = owner.lstat()
                if (owner != owner.resolve(strict=True) or owner.parent != self.control.parent
                        or re.fullmatch('nethub-cold-recovery-[a-f0-9]{16}', owner.name) is None
                        or self.ownership_record.name != 'witness.json' or info.st_uid != 0
                        or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700):
                    raise WitnessError('Independent parent cleanup ownership record refused')
                # The outer guard learns this namespace BEFORE any CA resource
                # or service is created, including a failed witness startup.
                write_json(self.ownership_record, {'version': 1, 'control': str(self.control)})
            for unit in (self.service + '.service', self.guard + '.service', self.guard + '.timer'):
                if property_value(self.control, unit, 'LoadState') != 'not-found':
                    raise WitnessError('New witness unit identity already exists')
            for kind, name in (('container', 'nethub-acme-test-' + nonce),
                               ('network', 'nethub-acme-test-' + nonce + '-network')):
                if inspect(self.control, kind, name) is not None:
                    raise WitnessError('New witness resource identity already exists')
            images = json.loads(command(self.control, ['docker', 'image', 'inspect', IMAGE]).stdout)
            if len(images) != 1 or images[0]['Os'] != 'linux' or images[0]['Architecture'] != 'amd64':
                raise WitnessError('Pinned witness image unavailable')
            content = self.binary.read_bytes()
            program = self.control / 'guiacme.test'
            program.write_bytes(content)
            program.chmod(0o555)
            recovery = self.control / 'cleanup.py'
            recovery.write_bytes(Path(__file__).read_bytes())
            recovery.chmod(0o600)
            write_json(self.control / 'state.json', {'version': 1, 'nonce': nonce,
                       'image_id': images[0]['Id'], 'binary_sha256': hashlib.sha256(content).hexdigest()})
            write_json(self.control / 'request.json', {'version': 1, 'host': self.host, 'forward_port': self.forward_port})
            (self.control / 'tmp').mkdir(mode=0o700)
            log = self.control / 'test-private.log'
            log.touch(mode=0o600, exist_ok=False)
            environment = {**ENVIRONMENT, **{key: os.environ[key]
                           for key in ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_TEMP')}}
            inherited = ['--setenv=' + key + '=' + value for key, value in environment.items()]
            command(self.control, ['/usr/bin/systemd-run', '--unit=' + self.guard, '--on-active=2520s',
                    '--property=UnsetEnvironment=GH_TOKEN GITHUB_TOKEN',
                    *inherited, '/usr/bin/python3', '-I', str(recovery), str(self.control)])
            if (property_value(self.control, self.guard + '.timer', 'ActiveState') != 'active'
                    or property_value(self.control, self.guard + '.timer', 'Unit') != self.guard + '.service'):
                raise WitnessError('Independent witness cleanup timer not active')
            command(self.control, ['/usr/bin/systemd-run', '--unit=' + self.service,
                    '--description=NetHub isolated cold witness ' + nonce, '--service-type=exec',
                    '--property=UnsetEnvironment=GH_TOKEN GITHUB_TOKEN',
                    '--property=RuntimeMaxSec=2400', '--property=TimeoutStopSec=10', '--property=KillMode=control-group',
                    '--property=RemainAfterExit=yes',
                    '--property=StandardOutput=append:' + str(log), '--property=StandardError=append:' + str(log),
                    *inherited, '--setenv=NETHUB_GUIACME_TEST_NONCE=' + nonce,
                    '--setenv=NETHUB_COLD_WITNESS_CONTROL=' + str(self.control),
                    '--setenv=NETHUB_GUIACME_PEBBLE_IMAGE=' + IMAGE, '--setenv=TMPDIR=' + str(self.control / 'tmp'),
                    str(program), '-test.v', '-test.run=^TestColdHostACMEWitness$', '-test.timeout=2400s'])
            deadline = time.monotonic() + 90
            while not (self.control / 'ready.json').exists():
                if (time.monotonic() >= deadline
                        or property_value(self.control, self.service + '.service', 'ActiveState') != 'active'):
                    raise WitnessError('Independent witness did not become ready; private log retained')
                time.sleep(.2)
            self.ready = private_json(self.control / 'ready.json')
            from witness_contract import valid_ready
            if not valid_ready(self.ready, self.host, str(self.control)):
                raise WitnessError('Independent witness ready contract refused')
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def finish(self):
        if self.control is None:
            raise WitnessError('Running independent witness required')
        descriptor = os.open(self.control / 'finish', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        deadline = time.monotonic() + 40
        while property_value(self.control, self.service + '.service', 'SubState') != 'exited':
            if (time.monotonic() >= deadline
                    or property_value(self.control, self.service + '.service', 'ActiveState') != 'active'):
                raise WitnessError('Independent witness completion failed or timed out')
            time.sleep(.2)
        result = private_json(self.control / 'witness-result.json')
        if (result != {'actual_CA_source_HTTP01_response': True, 'full_host_recovery_accepted': False}
                or property_value(self.control, self.service + '.service', 'Result') != 'success'
                or property_value(self.control, self.service + '.service', 'ExecMainStatus') != '0'):
            raise WitnessError('Independent genuine CA response not confirmed')
        return result

    def __exit__(self, *_):
        if self.control is None or not (self.control / 'state.json').exists():
            return
        cleanup(self.control)
        for suffix in ('.timer', '.service'):
            unit = self.guard + suffix
            if property_value(self.control, unit, 'LoadState') == 'not-found':
                continue
            command(self.control, ['/usr/bin/systemctl', 'stop', unit])
            if property_value(self.control, unit, 'ActiveState') not in ('inactive', 'failed'):
                raise WitnessError('Witness guard still active after owned cleanup')


if __name__ == '__main__':
    os.umask(0o077)
    try:
        if len(sys.argv) != 2:
            raise WitnessError('Owned witness cleanup path required')
        cleanup(Path(sys.argv[1]))
    except Exception:
        raise SystemExit('Owned witness cleanup failed; private state retained') from None
