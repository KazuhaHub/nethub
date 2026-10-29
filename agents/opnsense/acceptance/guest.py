"""Own one signed, disposable OPNsense guest on a fresh Linux CI runner."""
import base64
import bz2
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import urllib.request
import uuid


IMAGE = 'OPNsense-26.7-nano-amd64.img'
IMAGE_SHA256 = '28d5e2f37e40d87468a924e3006ef10e2ddc6de485b85333d9e3958c84d0cb9d'
KEY_SHA256 = '9f3b76ffef38fb6405595038b324b61043c9a2c375ae5c151d628508e9a845ce'
BASE = 'https://pkg.opnsense.org/releases/26.7/'
NATIVE_FIXTURE_PHASES = frozenset(('host_boundary', 'private_nonce', 'native_config_load',
    'native_security_checks', 'trust_ca_validation', 'trust_native_save', 'trust_legacy_binding',
    'trust_store_regeneration', 'native_gui_identity', 'native_gui_csr',
    'native_gui_leaf_validation', 'native_gui_save'))
ANNOUNCEMENT = ('https://raw.githubusercontent.com/opnsense/changelog/'
                'fd539a8f722f56354e117faa5ab1495a4ad14d5b/community/26.7/26.7')


class GuestError(Exception):
    """A fixed operation label; never expose private child output or arguments."""


def invoke(arguments, label, *, timeout=60, input=None):
    try:
        result = subprocess.run(arguments, input=input, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise GuestError(label + ' timed out') from None
    if result.returncode:
        raise GuestError(label + ' failed')
    return result.stdout


def download(url, target, maximum):
    total = 0
    with urllib.request.urlopen(url, timeout=60) as source, target.open('xb') as output:
        while part := source.read(1024 * 1024):
            total += len(part)
            if total > maximum:
                raise GuestError('Pinned download exceeds its limit')
            output.write(part)


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def supported_platform(version):
    match = re.fullmatch(r'26\.7\.([1-9][0-9]*)(?:_([1-9][0-9]*))?', version)
    return match is not None and (int(match[1]) > 1 or match[2] is not None)


def verified_image(directory):
    compressed, raw = directory / (IMAGE + '.bz2'), directory / IMAGE
    key, signature = directory / 'release.pub', directory / 'image.sig'
    download(BASE + compressed.name, compressed, 2 * 1024**3)
    download(BASE + 'OPNsense-26.7.pub', key, 16384)
    if digest(compressed) != IMAGE_SHA256 or digest(key) != KEY_SHA256:
        raise GuestError('Pinned image or release key changed')
    with urllib.request.urlopen(ANNOUNCEMENT, timeout=30) as response:
        announcement = response.read(131073).decode('utf-8')
    match = re.search(r'# -----BEGIN PUBLIC KEY-----.*?# -----END PUBLIC KEY-----', announcement, re.S)
    if match is None or '# SHA256 (' + compressed.name + ') = ' + IMAGE_SHA256 not in announcement:
        raise GuestError('Independent upstream image announcement differs')
    published = '\n'.join(line.removeprefix('# ') for line in match.group().splitlines())
    if published.strip() != key.read_text(encoding='ascii').strip():
        raise GuestError('Independent upstream release key differs')
    # Preserve sparse zero extents without changing any byte covered by the signature.
    size = 0
    with bz2.open(compressed, 'rb') as source, raw.open('xb') as output:
        while part := source.read(1024 * 1024):
            size += len(part)
            if size > 16 * 1024**3:
                raise GuestError('Release disk exceeds its limit')
            if part.strip(b'\0'):
                output.write(part)
            else:
                output.seek(len(part), os.SEEK_CUR)
        output.truncate(size)
    with urllib.request.urlopen(BASE + IMAGE + '.sig', timeout=30) as response:
        encoded = response.read(16385)
        if len(encoded) > 16384:
            raise GuestError('Release signature exceeds its limit')
        signature.write_bytes(base64.b64decode(b''.join(encoded.split()), validate=True))
    invoke(['openssl', 'dgst', '-sha256', '-verify', str(key), '-signature', str(signature), str(raw)],
           'release signature verification')
    checked = {'compressed_sha256': IMAGE_SHA256, 'raw_sha256': digest(raw), 'signature_verified': True}
    disk = directory / 'guest.qcow2'
    invoke(['qemu-img', 'convert', '-f', 'raw', '-O', 'qcow2', str(raw), str(disk)], 'disk conversion', timeout=120)
    invoke(['qemu-img', 'resize', str(disk), '16G'], 'owned disk expansion')
    invoke(['qemu-img', 'check', str(disk)], 'owned disk verification')
    raw.unlink()
    compressed.unlink()
    return disk, checked


class Console:
    def __init__(self, path, log):
        self.connection = socket.socket(socket.AF_UNIX)
        self.connection.settimeout(1)
        deadline = time.monotonic() + 30
        while True:
            try:
                self.connection.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    self.connection.close()
                    raise GuestError('Owned guest serial socket unavailable') from None
                time.sleep(.2)
        self.buffer = ''
        self.log = log.open('xb')

    def close(self):
        self.connection.close()
        self.log.close()

    def send(self, value):
        self.connection.sendall(value.encode('ascii'))

    def expect(self, expression, timeout, phase='serial_command'):
        self.phase = phase
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            clean = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', self.buffer)
            match = re.search(expression, clean, re.I | re.S)
            if match:
                self.buffer = clean[match.end():]
                return clean[:match.end()]
            try:
                part = self.connection.recv(65536)
            except socket.timeout:
                continue
            if not part:
                raise GuestError('Owned guest serial socket closed')
            self.log.write(part)
            self.log.flush()
            self.buffer = (self.buffer + part.decode('utf-8', errors='replace'))[-4 * 1024**2:]
        category = 'unclassified'
        for token, code in [('mountroot>', 'mountroot'), ('panic:', 'kernel_panic'),
                            ('configure VLANs', 'interface_assignment'),
                            ('WAN interface name', 'interface_assignment'),
                            ('Enter an option:', 'console_menu'), ('login:', 'login_prompt')]:
            if token.lower() in self.buffer.lower():
                category = code
        raise GuestError('Owned guest serial deadline exceeded: ' + phase + '/' + category)

    def login(self):
        self.expect(r'login:\s*$', 360, 'login_prompt')
        self.send('root\n')
        self.expect(r'Password:\s*$', 30, 'password_prompt')
        # Factory credentials exist only in the fresh, privately forwarded guest.
        self.send('opnsense\n')
        self.expect(r'Enter an option:', 120, 'console_menu')
        self.send('8\n')
        self.expect(r'[^\r\n]* #\s*$', 30, 'root_shell_prompt')
        self.send('/bin/sh\n')
        self.expect(r'#\s*$', 30, 'posix_shell_prompt')
        self.send("stty -echo; PS1='NH_SHELL> '; PS2='NH_MORE> '; export PS1 PS2; "
                  "printf '\\nNH_%s_READY\\n' SHELL\n")
        self.expect(r'NH_SHELL_READY\r?\n', 10, 'private_shell_marker')

    def command(self, script, timeout=60):
        marker = 'NH_' + uuid.uuid4().hex
        payload = base64.b64encode(script.encode('utf-8')).decode('ascii')
        # FreeBSD canonical terminal input has a short per-line bound. A quoted
        # heredoc keeps every encoded payload line and control line below it.
        delimiter = marker + '_DATA'
        deadline = time.monotonic() + timeout
        self.send("/usr/bin/base64 -d <<'" + delimiter + "' | /bin/sh\n")
        self.expect(r'NH_MORE> ', min(10, deadline - time.monotonic()), 'heredoc_header')
        for offset in range(0, len(payload), 96):
            self.send(payload[offset:offset + 96] + '\n')
            # A prompt acknowledges consumption before the next line enters the
            # finite serial input queue; a whole-script burst can overflow it.
            self.expect(r'NH_MORE> ', min(10, deadline - time.monotonic()), 'heredoc_payload')
        self.send(delimiter + "\nnh_exit=$?; printf '\\n" + marker + ":%s\\n' \"$nh_exit\"\n")
        value = self.expect(re.escape(marker) + r':([0-9]+)\r?\n',
                            deadline - time.monotonic(), 'bootstrap_exit')
        match = re.search(re.escape(marker) + r':([0-9]+)\r?\n', value)
        self.last_command_exit = int(match.group(1))
        if self.last_command_exit != 0:
            raise GuestError('Owned guest bootstrap command failed')
        return value[:match.start()]


class Guest:
    """Close only this process; the caller owns disposal of its private directory."""
    def __init__(self, directory):
        if (os.name != 'posix' or os.uname().sysname != 'Linux'
                or os.environ.get('GITHUB_ACTIONS') != 'true'
                or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
                or not Path('/dev/kvm').is_char_device()):
            raise GuestError('Fresh Linux CI with KVM is required')
        self.directory = Path(directory).absolute()
        if self.directory != self.directory.resolve():
            raise GuestError('Aliased guest storage refused')
        self.directory.mkdir(mode=0o700)
        self.process = None
        self.console = None
        self.qemu_log = None

    def __enter__(self):
        try:
            disk, self.image_receipt = verified_image(self.directory)
            invoke(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'nethub-ci-client',
                    '-f', str(self.directory / 'client-key')], 'ephemeral SSH client key')
            listeners = [socket.socket(), socket.socket()]
            try:
                for listener in listeners:
                    listener.bind(('127.0.0.1', 0))
                self.ssh_port, self.gui_port = [listener.getsockname()[1] for listener in listeners]
            finally:
                for listener in listeners:
                    listener.close()
            self.qemu_log = (self.directory / 'qemu-private.log').open('xb')
            self.process = subprocess.Popen([
                'qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '3072', '-smp', '2',
                '-drive', f'file={disk},format=qcow2,if=virtio', '-display', 'none', '-monitor', 'none',
                '-serial', f'unix:{self.directory / "serial.sock"},server=on,wait=off',
                '-netdev', f'user,id=lan,net=192.168.1.0/24,host=192.168.1.2,restrict=on,'
                           f'hostfwd=tcp:127.0.0.1:{self.ssh_port}-192.168.1.1:2222,'
                           f'hostfwd=tcp:127.0.0.1:{self.gui_port}-192.168.1.1:443',
                '-device', 'e1000,netdev=lan',
                '-netdev', 'user,id=wan,net=10.0.2.0/24', '-device', 'e1000,netdev=wan',
            ], stdin=subprocess.DEVNULL, stdout=self.qemu_log, stderr=self.qemu_log)
            self.console = Console(self.directory / 'serial.sock', self.directory / 'serial-private.log')
            self.console.login()
            public = (self.directory / 'client-key.pub').read_text(encoding='ascii').strip()
            script = """set -eu
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
install -d -m 0700 /root/nethub-ci
printf '\\nNH_%s_PHASE\\n' OWNED_DIRECTORY
ssh-keygen -q -t ed25519 -N '' -C nethub-ci-host -f /root/nethub-ci/host-key
printf '\\nNH_%s_PHASE\\n' HOST_KEY_CREATED
printf '%s\\n' '""" + public + """' > /root/nethub-ci/authorized_keys
cat > /root/nethub-ci/sshd.conf <<'CONFIG'
ListenAddress 192.168.1.1
Port 2222
HostKey /root/nethub-ci/host-key
PidFile /root/nethub-ci/sshd.pid
AuthorizedKeysFile /root/nethub-ci/authorized_keys
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
UseDNS no
Subsystem sftp internal-sftp
CONFIG
test -d /var/empty || install -d -m 0755 /var/empty
ssh_daemon=$(command -v sshd)
case "$ssh_daemon" in /usr/local/sbin/sshd|/usr/sbin/sshd) ;; *) exit 127 ;; esac
"$ssh_daemon" -f /root/nethub-ci/sshd.conf -E /root/nethub-ci/sshd-private.log
printf '\\nNH_%s_PHASE\\n' SSHD_STARTED
cat /root/nethub-ci/host-key.pub
"""
            response = self.console.command(script)
            host = re.findall(r'ssh-ed25519 [A-Za-z0-9+/=]+', response)
            if len(host) != 1:
                raise GuestError('Guest SSH host key was not confirmed over the signed-image console')
            (self.directory / 'known_hosts').write_text(f'[127.0.0.1]:{self.ssh_port} {host[0]}\n', encoding='ascii')
            self.ssh('test "$(id -u)" = 0\n', 'native root boundary')
            return self
        except Exception:
            self.bootstrap_failure_codes = []
            self.bootstrap_failure_wait_phase = getattr(self.console, 'phase', None)
            self.bootstrap_failure_exit = getattr(self.console, 'last_command_exit', None)
            if self.bootstrap_failure_exit == 127:
                self.bootstrap_failure_codes.append('bootstrap_missing_command')
            if self.console is not None and hasattr(self.console, 'last_command_exit'):
                try:
                    diagnostic = self.console.command(
                        "if test -f /root/nethub-ci/sshd-private.log; then tail -n 15 /root/nethub-ci/sshd-private.log; fi\n"
                        "if /sbin/ifconfig -a | grep -q 'inet 192.168.1.1 '; then printf '\\nNH_LAN_ADDRESS_PRESENT\\n'; fi\n"
                        "for interface in em0 em1; do if /sbin/ifconfig \"$interface\" inet | grep -q 'inet 192.168.1.1 '; then printf '\\nNH_LAN_ON_%s\\n' \"$interface\"; fi; done\n"
                        "true\n", timeout=15)
                    for needle, code in [('already in use', 'sshd_port_in_use'),
                                         ('Cannot assign requested address', 'sshd_listen_address_unavailable'),
                                         ('Missing privilege separation directory', 'sshd_privsep_directory'),
                                         ('Bad configuration option', 'sshd_configuration'),
                                         ('no hostkeys available', 'sshd_host_keys'),
                                         ('Failed publickey', 'sshd_public_key_refused'),
                                         ('Authentication refused', 'sshd_key_permissions'),
                                         ('not allowed', 'sshd_account_refused'),
                                         ('NH_LAN_ON_em0', 'factory_lan_on_em0'),
                                         ('NH_LAN_ON_em1', 'factory_lan_on_em1'),
                                         ('NH_LAN_ADDRESS_PRESENT', 'configured_lan_address_present')]:
                        if needle.lower() in diagnostic.lower():
                            self.bootstrap_failure_codes.append(code)
                except Exception:
                    self.bootstrap_failure_codes.append('private_probe_unavailable')
            self.__exit__(None, None, None)
            raise

    def ssh_options(self):
        return ['-i', str(self.directory / 'client-key'), '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'UserKnownHostsFile=' + str(self.directory / 'known_hosts'),
                '-o', 'ConnectTimeout=10']

    def ssh(self, script, label, timeout=60):
        args = ['ssh', *self.ssh_options(), '-p', str(self.ssh_port), 'root@127.0.0.1', '/bin/sh', '-s']
        try:
            result = subprocess.run(args, input=script.encode('utf-8'), capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise GuestError(label + ' timed out') from None
        log = self.directory / ('ssh-' + uuid.uuid4().hex + '-private.log')
        log.write_bytes(result.stdout + result.stderr)
        if result.returncode:
            category = 'unclassified'
            text = (result.stdout + result.stderr).decode('utf-8', errors='replace').lower()
            for token, code in [('no space left', 'disk_space'), ('certificate verify failed', 'download_tls'),
                                ('not found', 'missing_dependency'), ('fatal error', 'php_failure'),
                                ('differs from server/.go-version', 'compiler_mismatch'),
                                ('no address record', 'guest_dns'), ('operation timed out', 'guest_network'),
                                ('permission denied', 'guest_ssh_authentication'),
                                ('host key verification failed', 'guest_ssh_host_key'),
                                ('connection refused', 'guest_ssh_connection_refused'),
                                ('connection timed out', 'guest_ssh_connect_timeout'),
                                ('connection reset', 'guest_ssh_connection_reset')]:
                if token in text:
                    category = code
            if len(result.stdout) <= 4096:
                try:
                    value = json.loads(result.stdout)
                    if (isinstance(value, dict) and set(value) == {'success', 'fixture_phase'}
                            and value['success'] is False and value['fixture_phase'] in NATIVE_FIXTURE_PHASES):
                        category = 'fixture_' + value['fixture_phase']
                except (ValueError, TypeError):
                    pass
            raise GuestError(label + ' failed: ' + category)
        return result.stdout

    def ensure_ssh(self):
        try:
            self.ssh('test "$(id -u)" = 0\n', 'existing owned SSH probe', timeout=15)
            return
        except GuestError:
            # OPNsense service regeneration can stop all openssh listener
            # processes. Restart only our private configuration through serial;
            # retain its original host key and never accept a replacement key.
            self.console.command("set -eu\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                                 "export PATH\nssh_daemon=$(command -v sshd)\n"
                                 "case \"$ssh_daemon\" in /usr/local/sbin/sshd|/usr/sbin/sshd) ;; *) exit 127 ;; esac\n"
                                 "\"$ssh_daemon\" -f /root/nethub-ci/sshd.conf -E /root/nethub-ci/sshd-private.log\n")
            self.ssh('test "$(id -u)" = 0\n', 'restored owned SSH boundary', timeout=15)

    def put(self, path, name):
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}', name):
            raise GuestError('Invalid private guest staging name')
        invoke(['scp', '-O', *self.ssh_options(), '-P', str(self.ssh_port), str(path),
                'root@127.0.0.1:/root/nethub-ci/' + name], 'private guest input transfer')

    def __exit__(self, *_):
        self.exit_status_before_cleanup = self.process.poll() if self.process is not None else None
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.console is not None:
            self.console.close()
        if self.qemu_log is not None:
            self.qemu_log.close()

    def diagnostics(self):
        value = {'image': getattr(self, 'image_receipt', None),
                 'serial_wait_phase': getattr(self, 'bootstrap_failure_wait_phase', getattr(self.console, 'phase', None)),
                 'bootstrap_command_exit': getattr(self, 'bootstrap_failure_exit', None),
                 'guest_exit_status_before_cleanup': getattr(self, 'exit_status_before_cleanup', None),
                 'guest_exit_status_after_cleanup': self.process.poll() if self.process is not None else None,
                 'bootstrap_failure_codes': getattr(self, 'bootstrap_failure_codes', [])}
        path = self.directory / 'serial-private.log'
        if path.exists():
            value['serial_bytes'] = path.stat().st_size
            with path.open('rb') as source:
                source.seek(max(0, value['serial_bytes'] - 131072))
                text = source.read(131072).decode('utf-8', errors='replace')
            value['serial_markers'] = {name: needle in text for name, needle in {
                'product_banner': 'OPNsense', 'login_prompt': 'login:', 'password_prompt': 'Password:',
                'console_menu': 'Enter an option:', 'private_shell_ready': 'NH_SHELL_READY',
                'private_shell_prompt': 'NH_SHELL>', 'rejected_login': 'Login incorrect',
                'heredoc_prompt': 'NH_MORE>', 'owned_directory': 'NH_OWNED_DIRECTORY_PHASE',
                'host_key_created': 'NH_HOST_KEY_CREATED_PHASE', 'sshd_started': 'NH_SSHD_STARTED_PHASE',
            }.items()}
        return value
