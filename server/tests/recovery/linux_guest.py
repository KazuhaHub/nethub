"""Own a new Linux recovery target on an isolated hosted runner."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid


IMAGE = 'noble-server-cloudimg-amd64.img'
BASE = 'https://cloud-images.ubuntu.com/noble/20261017/'
IMAGE_SHA256 = '04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94'
SIGNER = 'D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'


class RecoveryError(Exception):
    """Only fixed operation labels may reach public diagnostics."""


def invoke(arguments, label, *, timeout=60, data=None):
    try:
        result = subprocess.run(arguments, input=data, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise RecoveryError(label + ' unavailable or timed out') from None
    if result.returncode:
        raise RecoveryError(label + ' failed')
    return result.stdout


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def download(url, target, maximum):
    # Downloads are called only with the pinned Canonical URLs below.
    total = 0
    with urllib.request.urlopen(url, timeout=60) as response, target.open('xb') as output:
        final = urllib.parse.urlsplit(response.url)
        if final.scheme != 'https' or final.hostname not in ('cloud-images.ubuntu.com', 'keyserver.ubuntu.com'):
            raise RecoveryError('Cloud image download redirect refused')
        while block := response.read(1024 * 1024):
            total += len(block)
            if total > maximum:
                raise RecoveryError('Cloud image download exceeded its limit')
            output.write(block)


def verify_checksum_list(raw):
    try:
        matches = [line.split() for line in raw.decode('ascii').splitlines()
                   if line.split() and line.split()[-1].lstrip('*') == IMAGE]
    except UnicodeError:
        raise RecoveryError('Cloud image checksum list refused') from None
    if len(matches) != 1 or matches[0] != [IMAGE_SHA256, '*' + IMAGE]:
        raise RecoveryError('Pinned cloud image checksum differs')


def verify_signer(status):
    try:
        valid = [line.split()[2:] for line in status.decode('ascii').splitlines()
                 if line.startswith('[GNUPG:] VALIDSIG ')]
    except UnicodeError:
        raise RecoveryError('Cloud image signer differs') from None
    if len(valid) != 1 or len(valid[0]) != 10 or valid[0][0] != SIGNER or valid[0][-1] != SIGNER:
        raise RecoveryError('Cloud image signer differs')


def verified_image(directory):
    for name, maximum in [('SHA256SUMS', 256 * 1024), ('SHA256SUMS.gpg', 16384)]:
        download(BASE + name, directory / name, maximum)
    verify_checksum_list((directory / 'SHA256SUMS').read_bytes())
    key = directory / 'cloud-signing-key.asc'
    download('https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x' + SIGNER, key, 128 * 1024)
    home = directory / 'gnupg'
    home.mkdir(mode=0o700)
    keyring = home / 'cloud.gpg'
    invoke(['gpg', '--homedir', str(home), '--batch', '--no-default-keyring', '--keyring', str(keyring),
            '--import', str(key)], 'Canonical cloud signing key import')
    status = invoke(['gpgv', '--homedir', str(home), '--keyring', str(keyring), '--status-fd', '1',
                     str(directory / 'SHA256SUMS.gpg'), str(directory / 'SHA256SUMS')],
                    'Canonical signed checksum verification')
    verify_signer(status)
    disk = directory / IMAGE
    download(BASE + IMAGE, disk, 1024**3)
    if sha256(disk) != IMAGE_SHA256:
        raise RecoveryError('Cloud image content differs')
    info = json.loads(invoke(['qemu-img', 'info', '--output=json', str(disk)], 'Cloud disk inspection'))
    if info.get('format') != 'qcow2' or 'backing-filename' in info or info['virtual-size'] > 16 * 1024**3:
        raise RecoveryError('Unexpected cloud disk format or backing image')
    invoke(['qemu-img', 'resize', str(disk), '24G'], 'Owned cloud disk expansion')
    invoke(['qemu-img', 'check', str(disk)], 'Owned cloud disk integrity')
    return disk


def cloud_config(client_public, host_private, host_public):
    return {'disable_root': False, 'ssh_pwauth': False, 'ssh_deletekeys': True,
            'ssh_keys': {'ed25519_private': host_private, 'ed25519_public': host_public},
            'users': [{'name': 'root', 'lock_passwd': True, 'ssh_authorized_keys': [client_public]}]}


def validate_identity(value, host_machine, host_boot):
    expected = {'machine_id', 'boot_id', 'os_id', 'os_version', 'empty_deployment', 'empty_database',
                'docker_version', 'compose_version', 'containers', 'volumes'}
    if (set(value) != expected or not re.fullmatch('[0-9a-f]{32}', value['machine_id'])
            or not re.fullmatch('[0-9a-f-]{36}', value['boot_id'])
            or value['machine_id'] == host_machine or value['boot_id'] == host_boot
            or value['os_id'] != 'ubuntu' or value['os_version'] != '24.04'
            or value['empty_deployment'] is not True or value['empty_database'] is not True
            or value['containers'] != [] or value['volumes'] != []
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+[^\s]*', value['docker_version'])
            or not re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+[^\s]*', value['compose_version'])):
        raise RecoveryError('Recovery target is not a distinct empty supported host')


class LinuxGuest:
    """The caller owns its private directory; this class owns only its QEMU process."""
    def __init__(self, directory):
        if (sys.platform != 'linux' or os.geteuid() != 0
                or os.environ.get('GITHUB_ACTIONS') != 'true'
                or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
                or not Path('/dev/kvm').is_char_device()):
            raise RecoveryError('Fresh root Linux hosted CI with KVM is required')
        parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        self.directory = Path(directory).absolute()
        if (self.directory != self.directory.resolve() or not self.directory.is_relative_to(parent)
                or self.directory == parent):
            raise RecoveryError('Private new hosted storage is required')
        self.directory.mkdir(mode=0o700)
        self.process = None
        self.log = None

    def __enter__(self):
        try:
            disk = verified_image(self.directory)
            for name in ('client', 'host'):
                invoke(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'recovery-fixture',
                        '-f', str(self.directory / name)], 'Ephemeral recovery SSH key creation')
            config = cloud_config((self.directory / 'client.pub').read_text().strip(),
                                  (self.directory / 'host').read_text(),
                                  (self.directory / 'host.pub').read_text().strip())
            user_data = self.directory / 'user-data'
            user_data.write_text('#cloud-config\n' + json.dumps(config) + '\n', encoding='utf-8')
            meta_data = self.directory / 'meta-data'
            meta_data.write_text(json.dumps({'instance-id': 'nethub-' + uuid.uuid4().hex,
                                            'local-hostname': 'recovery-target'}), encoding='utf-8')
            seed = self.directory / 'seed.img'
            invoke(['cloud-localds', str(seed), str(user_data), str(meta_data)], 'Private cloud-init seed')
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                self.port = listener.getsockname()[1]
            known = self.directory / 'known_hosts'
            known.write_text(f'[127.0.0.1]:{self.port} ' + config['ssh_keys']['ed25519_public'] + '\n')
            self.log = (self.directory / 'qemu-private.log').open('xb')
            self.process = subprocess.Popen([
                'qemu-system-x86_64', '-machine', 'q35,accel=kvm', '-cpu', 'host', '-m', '2048', '-smp', '2',
                '-display', 'none', '-monitor', 'none', '-serial', 'stdio',
                '-drive', f'file={disk},format=qcow2,if=virtio',
                '-drive', f'file={seed},format=raw,if=virtio,readonly=on',
                '-netdev', f'user,id=wan,hostfwd=tcp:127.0.0.1:{self.port}-:22',
                '-device', 'virtio-net-pci,netdev=wan'], stdin=subprocess.DEVNULL,
                stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RecoveryError('Owned recovery guest exited during boot')
                try:
                    self.ssh('true\n', 'Recovery SSH readiness', timeout=8)
                    break
                except RecoveryError:
                    time.sleep(2)
            else:
                raise RecoveryError('Recovery SSH readiness timed out')
            self.ssh('cloud-init status --wait >/dev/null\n', 'Cloud initialization', timeout=180)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def ssh(self, script, label, *, timeout=60):
        return invoke(['ssh', '-F', '/dev/null', '-i', str(self.directory / 'client'),
                       '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                       '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=5',
                       '-o', 'UserKnownHostsFile=' + str(self.directory / 'known_hosts'),
                       '-p', str(self.port), 'root@127.0.0.1', 'sh', '-se'],
                      label, timeout=timeout, data=script.encode())

    def prepare(self):
        self.ssh('export DEBIAN_FRONTEND=noninteractive\n'
                 'apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 update -qq\n'
                 'apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 install -y '
                 '--no-install-recommends docker.io docker-compose-v2 python3\n'
                 'systemctl enable --now docker\n', 'Recovery container runtime installation', timeout=600)
        value = json.loads(self.ssh('python3 - <<\'PY\'\n'
            'import json, pathlib, subprocess\n'
            'def out(*args): return subprocess.check_output(args).decode().strip()\n'
            'os_release = pathlib.Path("/etc/os-release").read_text()\n'
            'release = dict(line.split("=",1) for line in os_release.splitlines() if "=" in line)\n'
            'print(json.dumps({"machine_id": pathlib.Path("/etc/machine-id").read_text().strip(),\n'
            '"boot_id": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),\n'
            '"os_id": release["ID"].strip(chr(34)), "os_version": release["VERSION_ID"].strip(chr(34)),\n'
            '"empty_deployment": not pathlib.Path("/root/nethub-recovery").exists(),\n'
            '"empty_database": not pathlib.Path("/var/lib/postgresql").exists(),\n'
            '"docker_version": out("docker","version","--format","{{.Server.Version}}"),\n'
            '"compose_version": out("docker","compose","version","--short"),\n'
            '"containers": out("docker","ps","-aq").splitlines(),\n'
            '"volumes": out("docker","volume","ls","-q").splitlines()}))\nPY\n',
            'Distinct empty recovery host inspection'))
        validate_identity(value, Path('/etc/machine-id').read_text().strip(),
                          Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        # Keep identifiers private. Published evidence contains only verified decisions.
        self.identity = value
        return {'distinct_machine': True, 'distinct_boot': True, 'empty_deployment': True,
                'empty_database': True, 'empty_containers': True, 'empty_volumes': True,
                'os': 'Ubuntu 24.04', 'docker_version': value['docker_version'],
                'compose_version': value['compose_version']}

    def __exit__(self, *_):
        if self.process is not None and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=10)
        if self.log is not None:
            self.log.close()
