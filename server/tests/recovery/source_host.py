"""Prepare the original cold-recovery host inside a fresh owned Linux guest.

This is preparation for the combined cold-host driver. It does not yet restore
an issuer, start its timers, enroll a client or establish recovery acceptance.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess

from image_archive import inspect_archive
from host_layout import DEPLOYMENT, HELPER, RECEIVE_LIMITS, ROLES, SERVICE_ROLES, SOURCE, TRANSFER, UNITS, valid_tags
from linux_guest import LinuxGuest, RecoveryError, sha256


def configure_profile(override, tags, caddy):
    if not isinstance(tags, dict):
        raise RecoveryError('Reviewed source image selection required')
    validate_selection(tags, dict.fromkeys(tags.values()))
    if (not isinstance(override, dict) or not isinstance(override.get('services'), dict)
            or not {'postgres', 'migrate', 'nethub-web', 'nethub-authz', 'frps', 'caddy'} <= set(override['services'])
            or set(override['services']) - set(SERVICE_ROLES)
            or caddy.count('{$NETHUB_CONSOLE_HOST} {') != 1):
        raise RecoveryError('Original generated source profile differs from the reviewed fixture')
    selected = copy.deepcopy(override)
    for service, role in SERVICE_ROLES.items():
        selected['services'].setdefault(service, {})['image'] = tags[role]
    # Only this isolated console uses Caddy's private CA. The device HTTP-01
    # route is added later from the actual publisher renderer, not recreated here.
    caddy = caddy.replace('{$NETHUB_CONSOLE_HOST} {', 'https://console.example.com {\n    tls internal', 1)
    return selected, caddy


def validate_selection(tags, inspected):
    if not valid_tags(tags) or set(inspected) != set(tags.values()):
        raise RecoveryError('Exactly five previously tested recovery image roles required')


class DeploymentHost:
    def __init__(self, guest, repository, *, role='source'):
        if (type(guest) is not LinuxGuest or guest.process is None
                or guest.process.poll() is not None):
            raise RecoveryError('Live owned hosted Linux guest required')
        if role not in ('source', 'target'):
            raise RecoveryError('Owned source or target guest role required')
        self.guest, self.repository = guest, Path(repository).resolve(strict=True)
        self.head = os.environ.get('NETHUB_SOURCE_HEAD', '')
        if re.fullmatch('[a-f0-9]{40}', self.head) is None:
            raise RecoveryError('Exact recovery source head required')
        self.work = guest.directory / (role + '-bootstrap')
        self.work.mkdir(mode=0o700)
        self.counter = 0
        self.host_prepared = False
        self.bootstrap_completed = False
        self.stack_started = False
        self.issuer_configured = False

    def command(self, args, label, *, output=None, data=None, timeout=60):
        self.counter += 1
        try:
            result = subprocess.run(args, cwd=self.repository, input=data,
                                    stdout=output if output is not None else subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise RecoveryError(label + ' unavailable or timed out') from None
        (self.work / f'step-{self.counter}.log').write_bytes(
            (result.stdout if output is None else b'') + result.stderr)
        if result.returncode:
            raise RecoveryError(label + ' failed')
        return result.stdout

    def remote(self, args, label, *, timeout=60):
        return self.script(shlex.join(args) + '\n', label, timeout=timeout)

    def script(self, script, label, *, timeout=60):
        return self.command(self.guest.ssh_arguments() + ['root@127.0.0.1', 'sh', '-se'],
                            label, data=script.encode(), timeout=timeout)

    def send_module(self, name):
        destination = self.work / name
        destination.write_bytes(self.command(['git', 'show', self.head + ':server/tests/recovery/' + name],
                                            'Exact recovery helper source'))
        destination.chmod(0o600)
        return self.guest.send(destination, name)

    def prepare_images(self, images, tags):
        if self.host_prepared:
            raise RecoveryError('Owned host preparation cannot be repeated')
        # The caller's producer gate must already bind the archive to this exact
        # successful CI source. Content verification here is a separate check.
        if self.command(['git', 'rev-parse', 'HEAD'], 'Recovery source identity').decode().strip() != self.head:
            raise RecoveryError('Recovery checkout differs from the selected source')
        inspected = inspect_archive(Path(images))
        validate_selection(tags, inspected)
        prepared = self.guest.prepare()
        self.script('umask 077\nmkdir /root/nethub-recovery\n', 'New private source transfer namespace')
        remote_images = self.guest.send(images, 'images.tar')
        self.remote(['docker', 'load', '-i', remote_images], 'Original guest image load', timeout=180)
        verifier = self.send_module('image_archive.py')
        exported = '/root/nethub-recovery/reloaded-images.tar'
        self.remote(['docker', 'image', 'save', '-o', exported, *sorted(tags.values())],
                    'Original guest loaded image export', timeout=180)
        actual = json.loads(self.remote(['python3', verifier, exported],
                                       'Original guest complete image verification', timeout=180))
        if actual != inspected:
            raise RecoveryError('Original guest image configuration or layers differ')
        self.tags = dict(tags)
        self.host_prepared = True
        return prepared

    def install_file(self, data, transfer_name, destination, mode):
        source = self.work / transfer_name
        with source.open('xb') as output:
            output.write(data)
        source.chmod(0o600)
        remote = self.guest.send(source, transfer_name)
        self.remote(['install', '-o', 'root', '-g', 'root', '-m', mode, remote, destination],
                    'Owned recovery profile installation')
        actual = self.remote(['sha256sum', destination], 'Owned recovery profile exact readback').split()[0].decode()
        if actual != hashlib.sha256(data).hexdigest():
            raise RecoveryError('Owned recovery profile readback differs')

    def receive(self, name):
        if name not in RECEIVE_LIMITS:
            raise RecoveryError('Private checkpoint export name refused')
        if not getattr(self, 'transfer_module', None):
            self.send_module('host_layout.py')
            self.transfer_module = self.send_module('checkpoint_transfer.py')
        info = json.loads(self.remote(['python3', self.transfer_module, 'info', name],
                                     'Private guest checkpoint export identity'))
        if (set(info) != {'bytes', 'sha256'} or type(info['bytes']) is not int
                or not 0 < info['bytes'] <= RECEIVE_LIMITS[name]
                or re.fullmatch('[a-f0-9]{64}', info['sha256']) is None):
            raise RecoveryError('Private guest checkpoint export metadata refused')
        destination = self.work / name
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            self.command(self.guest.ssh_arguments() + ['root@127.0.0.1',
                shlex.join(['python3', self.transfer_module, 'read', name])],
                'Private guest checkpoint transfer', output=output, timeout=180)
            output.flush()
            os.fsync(output.fileno())
        if destination.stat().st_size != info['bytes'] or sha256(destination) != info['sha256']:
            raise RecoveryError('Private guest checkpoint transfer differs')
        return destination


class SourceHost(DeploymentHost):
    def bootstrap(self, images, tags):
        if self.bootstrap_completed:
            raise RecoveryError('Source host bootstrap cannot be repeated')
        prepared = self.prepare_images(images, tags)

        source = self.work / 'source.tar'
        with source.open('xb') as output:
            self.command(['git', '-c', 'core.autocrlf=false', '-c', 'tar.umask=0022',
                          'archive', '--format=tar', self.head],
                         'Exact tracked recovery source export', output=output)
        source.chmod(0o600)
        remote_source = self.guest.send(source, 'source.tar')
        extractor = self.send_module('source_archive.py')
        extracted = json.loads(self.remote(['python3', extractor, remote_source, SOURCE, sha256(source), self.head],
                                          'New original guest source extraction'))
        if extracted.get('source_archive_verified') is not True:
            raise RecoveryError('Original guest source extraction was not confirmed')

        self.script('test ! -e ' + HELPER + '\nmkdir -p /usr/local/libexec\n',
                       'Unused original guest helper location')
        container = self.remote(['docker', 'create', '--network', 'none', '--read-only',
            '--label', 'org.nethub.recovery-source=' + self.head, tags['runtime']],
            'Tested helper extraction container').decode().strip()
        if re.fullmatch('[a-f0-9]{64}', container) is None:
            raise RecoveryError('Owned helper extraction container identity refused')
        try:
            self.remote(['docker', 'cp', container + ':/nethub', HELPER], 'Tested original host helper extraction')
            self.remote(['chown', '0:0', HELPER], 'Original host helper ownership')
            self.remote(['chmod', '0555', HELPER], 'Original host helper mode')
        finally:
            self.remote(['docker', 'rm', container], 'Owned helper extraction container removal')

        for unit in UNITS:
            destination = '/etc/systemd/system/' + unit
            self.script('test ! -e ' + shlex.quote(destination) + '\n',
                           'Unused persistent issuer unit location')
            self.remote(['install', '-o', 'root', '-g', 'root', '-m', '0644',
                         SOURCE + '/deploy/systemd/' + unit, destination], 'Original persistent issuer unit installation')
            expected = hashlib.sha256(self.command(['git', 'show',
                self.head + ':deploy/systemd/' + unit], 'Exact persistent issuer unit source')).hexdigest()
            actual = self.remote(['sha256sum', destination], 'Persistent issuer unit readback').split()[0].decode()
            if actual != expected:
                raise RecoveryError('Original persistent issuer unit bytes differ')
        self.remote(['systemctl', 'daemon-reload'], 'Original persistent unit loading')
        for unit in UNITS:
            for prop, expected in [('LoadState', 'loaded'), ('FragmentPath', '/etc/systemd/system/' + unit),
                                   ('DropInPaths', ''), ('ActiveState', 'inactive'),
                                   ('UnitFileState', 'disabled' if unit.endswith('.timer') else 'static')]:
                value = self.remote(['systemctl', 'show', unit, '--property=' + prop, '--value'],
                                    'Inactive original persistent unit verification').decode().strip()
                if value != expected:
                    raise RecoveryError('Original persistent unit binding or inactive intent differs')
        self.tags = dict(tags)
        self.bootstrap_completed = True
        return {'host': prepared, 'same_tested_image_content': True,
                'exact_tracked_source': True, 'exact_stock_persistent_units_loaded_inactive': True,
                'issuer_restored_or_recovery_accepted': False}

    def initialize_stack(self):
        if not self.bootstrap_completed or self.stack_started:
            raise RecoveryError('New verified source host bootstrap required before initialization')
        self.script('test ! -e ' + DEPLOYMENT + '\n'
                    'test ! -e /var/backups/nethub\n'
                    'install -d -o root -g root -m 0700 /var/backups/nethub\n',
                    'Empty source deployment and protected backup parent')
        initialization = [HELPER, 'init', '--offline', '--source-directory', SOURCE,
                          '--directory', DEPLOYMENT, '--backup-directory', '/var/backups/nethub/initial',
                          '--console-host', 'console.example.com', '--device-domain', 'devices.example.test']
        self.script("printf '%s\\n' 'I HAVE VERIFIED THE NETHUB SECRET BACKUP' | " +
                    shlex.join(initialization) + '\n', 'Original guest confirmed initialization')
        override = json.loads(self.remote(['cat', DEPLOYMENT + '/docker-compose.override.yml'],
                                          'Original generated Compose profile read'))
        caddy = self.remote(['cat', DEPLOYMENT + '/Caddyfile'], 'Original generated console route read').decode()
        override, caddy = configure_profile(override, self.tags, caddy)
        self.install_file((json.dumps(override, indent=2) + '\n').encode(), 'source-override.json',
                          DEPLOYMENT + '/docker-compose.override.yml', '0600')
        self.install_file(caddy.encode(), 'source-console.caddy', DEPLOYMENT + '/Caddyfile', '0644')
        self.compose = ['docker', 'compose', '--project-name', 'nethub',
                        '--file', DEPLOYMENT + '/docker-compose.yml',
                        '--file', DEPLOYMENT + '/docker-compose.override.yml']
        self.remote([HELPER, 'doctor', '--directory', DEPLOYMENT], 'Original confirmed files and independent backup')
        self.remote(self.compose + ['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '150'],
                    'Original source six-service startup', timeout=210)
        identities = self.remote(self.compose + ['ps', '-q'], 'Original source running inventory').decode().splitlines()
        if len(identities) != 6 or any(re.fullmatch('[a-f0-9]{64}', value) is None for value in identities):
            raise RecoveryError('Exactly six original source services required')
        inspected = json.loads(self.remote(['docker', 'inspect', *identities], 'Original source service ownership'))
        services = {}
        for value in inspected:
            labels = value['Config']['Labels']
            service = labels.get('com.docker.compose.service')
            if (labels.get('com.docker.compose.project') != 'nethub'
                    or service not in SERVICE_ROLES or service in services
                    or value['State']['Running'] is not True
                    or value['Config']['Image'] != self.tags[SERVICE_ROLES[service]]):
                raise RecoveryError('Original source service ownership or selected image differs')
            services[service] = value
        if set(services) != {'postgres', 'backup', 'nethub-web', 'nethub-authz', 'frps', 'caddy'}:
            raise RecoveryError('Original source running service set differs')
        self.services = services
        self.remote([HELPER, 'doctor', '--directory', DEPLOYMENT, '--runtime-containers', '--project', 'nethub'],
                    'Original source actual runtime separation')
        # Keep the temporary password in this guest's private transfer namespace.
        # The driver obtains it privately for normal HTTPS administrator login.
        self.script("python3 - <<'PY'\nimport os,secrets\nos.umask(0o077)\n"
                    "with open('/root/nethub-recovery/admin-password','xb') as f:\n"
                    " f.write((secrets.token_urlsafe(32)+'\\n').encode())\nPY\n"
                    'cat /root/nethub-recovery/admin-password | ' + shlex.join(self.compose +
                    ['run', '--rm', '-T', 'admin-bootstrap', '--email', 'cold-admin@example.com', '--password-stdin']) + '\n',
                    'Original source first administrator', timeout=90)
        self.stack_started = True
        return {'confirmed_original_keys_and_backup': True, 'same_tested_six_services_running': True,
                'actual_runtime_separation_checked': True, 'first_administrator_created': True,
                'issuer_or_complete_cold_recovery_accepted': False}

    def configure_issuer(self, witness, assigned_host):
        if (not self.stack_started or self.issuer_configured or witness.get('version') != 1
                or witness.get('host') != assigned_host
                or re.fullmatch('[a-z0-9]{8}\\.devices\\.example\\.test', assigned_host) is None):
            raise RecoveryError('Original stack and matching owned witness required')
        snapshot = Path(witness['account_backup_directory'])
        info = snapshot.lstat()
        if (snapshot != snapshot.resolve(strict=True) or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700
                or {p.name for p in snapshot.iterdir()} != {'account.json', 'account.lock'}):
            raise RecoveryError('Complete registered private account snapshot required')
        self.script('test ! -e /etc/nethub\n'
                    'test ! -e /var/lib/nethub-gui-acme\n'
                    'test ! -e /var/backups/nethub/gui-account-registered\n'
                    'install -d -o root -g root -m 0700 /etc/nethub /var/backups/nethub/gui-account-registered\n',
                    'New original protected issuer namespaces')
        for name in ('account.json', 'account.lock'):
            source = snapshot / name
            info = source.lstat()
            if (source != source.resolve(strict=True) or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 <= info.st_size <= 32768 or name == 'account.lock' and info.st_size != 0):
                raise RecoveryError('Private account snapshot member refused')
            remote = self.guest.send(source, 'registered-' + name)
            destination = '/var/backups/nethub/gui-account-registered/' + name
            self.remote(['install', '-o', 'root', '-g', 'root', '-m', '0600', remote, destination],
                        'Original registered account snapshot transfer')
            actual = self.remote(['sha256sum', destination], 'Original registered account snapshot readback').split()[0].decode()
            if actual != sha256(source):
                raise RecoveryError('Original registered account snapshot differs')
        for field, name in (('api_roots_file', 'acme-api-root.pem'), ('certificate_roots_file', 'gui-certificate-root.pem')):
            source = Path(witness[field])
            info = source.lstat()
            if (source != source.resolve(strict=True) or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 < info.st_size <= 65536):
                raise RecoveryError('Owned witness public trust file refused')
            self.install_file(source.read_bytes(), name, '/etc/nethub/' + name, '0600')
        http_policy = {'version': 1, 'public_directory': '/srv/nethub-http01',
                       'state_directory': '/var/lib/nethub-http01', 'device_domain': 'devices.example.test',
                       'excluded_hosts': ['console.example.com']}
        issuer_policy = {'version': 1, 'account_directory': '/var/lib/nethub-gui-acme',
                         'directory_url': witness['directory_url'], 'contact_email': witness['contact_email'],
                         'additional_origins': [], 'api_roots_file': '/etc/nethub/acme-api-root.pem',
                         'certificate_roots_file': '/etc/nethub/gui-certificate-root.pem',
                         'http01_policy_file': '/etc/nethub/http01.json', 'cleanup_timer': 'nethub-http01-cleanup.timer'}
        for name, value in (('http01.json', http_policy), ('gui-issuer.json', issuer_policy)):
            self.install_file((json.dumps(value, indent=2) + '\n').encode(), name, '/etc/nethub/' + name, '0600')
        self.remote([HELPER, 'certificates', 'initialize-http01', '--directory', DEPLOYMENT,
                     '--config-file', '/etc/nethub/http01.json'], 'Original publisher initialization')
        account = [HELPER, 'certificates', 'account']
        options = ['--directory', DEPLOYMENT, '--config-file', '/etc/nethub/gui-issuer.json']
        backup = ['--backup-directory', '/var/backups/nethub/gui-account-registered']
        self.remote(account + ['restore', *options, *backup], 'Original registered account restoration')
        self.remote(account + ['lookup', *options], 'Original registered account creation-disabled lookup')
        self.remote(account + ['verify-backup', *options, *backup], 'Original registered account snapshot verification')
        account_hash = self.remote(['sha256sum', '/var/lib/nethub-gui-acme/account.json'],
                                   'Original registered account exact identity readback').split()[0].decode()
        if account_hash != sha256(snapshot / 'account.json'):
            raise RecoveryError('Original registered account key or identity changed')
        route_file = Path(witness['http01_route_file'])
        info = route_file.lstat()
        if (route_file != route_file.resolve(strict=True) or not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 65536):
            raise RecoveryError('Owned witness publisher route file refused')
        route = route_file.read_text(encoding='utf-8')
        if not route.startswith(':80 {\n') or '/nethub-http01' not in route:
            raise RecoveryError('Owned publisher-rendered proxy route required')
        caddy = self.remote(['cat', DEPLOYMENT + '/Caddyfile'], 'Original private console route readback').decode()
        self.install_file((caddy + '\n' + route).encode(), 'issuer-route.caddy', DEPLOYMENT + '/Caddyfile', '0644')
        override = json.loads(self.remote(['cat', DEPLOYMENT + '/docker-compose.override.yml'],
                                          'Original selected Compose profile readback'))
        service = override['services']['caddy']
        if service.get('volumes'):
            raise RecoveryError('Unexpected original proxy override mounts')
        service['volumes'] = ['/srv/nethub-http01:/nethub-http01:ro']
        self.install_file((json.dumps(override, indent=2) + '\n').encode(), 'issuer-override.json',
                          DEPLOYMENT + '/docker-compose.override.yml', '0600')
        self.remote(self.compose + ['up', '-d', '--no-build', '--pull', 'never', '--no-deps', 'caddy'],
                    'Original public-only publisher route installation', timeout=90)
        self.remote(['systemctl', 'start', 'nethub-http01-cleanup.service'],
                    'Original independent stock publisher cleanup', timeout=60)
        for prop, expected in (('Result', 'success'), ('ExecMainStatus', '0')):
            if self.remote(['systemctl', 'show', 'nethub-http01-cleanup.service', '--property=' + prop, '--value'],
                           'Original independent cleanup execution readback').decode().strip() != expected:
                raise RecoveryError('Original independent cleanup failed')
        # Capture enabled intent while both timers are quiesced for maintenance.
        # Only the restored target will start the pending job's issuer timer.
        timers = ('nethub-http01-cleanup.timer', 'nethub-gui-issuer.timer')
        self.remote(['systemctl', 'enable', *timers], 'Original protected timer enabled intent')
        for timer in timers:
            for prop, expected in (('UnitFileState', 'enabled'), ('ActiveState', 'inactive')):
                if self.remote(['systemctl', 'show', timer, '--property=' + prop, '--value'],
                               'Original quiesced timer intent readback').decode().strip() != expected:
                    raise RecoveryError('Original issuer timer intent differs')
        self.account_hash = account_hash
        self.issuer_configured = True
        return {'original_registered_account_and_snapshot_retained': True,
                'stock_independent_cleanup_succeeded': True, 'public_only_HTTP01_proxy_installed': True,
                'persistent_timers_enabled_but_quiesced': True, 'full_host_recovery_accepted': False}

    def capture_checkpoint(self, native_device_id, pending_request_id):
        if not self.stack_started or not self.issuer_configured or getattr(self, 'checkpoint_created', False):
            raise RecoveryError('New complete source issuer configuration required')
        expected = {'version': 1, 'machine_id': self.guest.identity['machine_id'],
                    'boot_id': self.guest.identity['boot_id'], 'source_head': self.head, 'tags': self.tags,
                    'unit_hashes': {unit: hashlib.sha256(self.command(['git', 'show',
                        self.head + ':deploy/systemd/' + unit], 'Original stock unit identity')).hexdigest()
                        for unit in UNITS}, 'account_hash': self.account_hash,
                    'native_device_id': native_device_id, 'pending_request_id': pending_request_id}
        from host_checkpoint import valid_capture_input
        if not valid_capture_input(expected):
            raise RecoveryError('Original owned source checkpoint input differs')
        # host_layout may already be present when the original administrator
        # password was obtained privately before its normal HTTPS login.
        if not getattr(self, 'transfer_module', None):
            self.send_module('host_layout.py')
            self.transfer_module = self.send_module('checkpoint_transfer.py')
        for name in ('database.py', 'payload.py', 'host_checkpoint.py'):
            self.send_module(name)
        self.install_file((json.dumps(expected) + '\n').encode(), 'capture-input.json',
                          TRANSFER + '/capture-input.json', '0600')
        result = json.loads(self.remote(['python3', TRANSFER + '/host_checkpoint.py', 'capture'],
                                       'Original complete protected-host checkpoint', timeout=300))
        if result != {'consistent_private_checkpoint_created': True, 'original_services_and_issuer_stopped': True,
                      'same_pending_native_job_retained': True, 'source_guest_poweroff_verified': False,
                      'full_host_recovery_accepted': False}:
            raise RecoveryError('Original protected-host checkpoint was not confirmed')
        metadata = self.receive('checkpoint.json')
        payload = self.receive('current-files.tar')
        value = json.loads(metadata.read_text())
        if (value['source_head'] != self.head or value['source_machine_id'] != self.guest.identity['machine_id']
                or value['source_boot_id'] != self.guest.identity['boot_id']
                or value['payload']['sha256'] != sha256(payload)):
            raise RecoveryError('Original private checkpoint identity differs')
        self.checkpoint_created = True
        return metadata, payload
