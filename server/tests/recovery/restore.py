"""Rebuild the owned control plane while its original native client keeps running."""
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time

from database import fingerprint
from linux_guest import LinuxGuest, RecoveryError, sha256
from payload import pack


SERVICES = {'postgres', 'backup', 'nethub-web', 'nethub-authz', 'frps', 'caddy'}
WRITERS = ['backup', 'nethub-web', 'nethub-authz', 'frps', 'caddy']
VOLUMES = {'database-backups', 'caddy-data', 'caddy-config'}


class Restore:
    def __init__(self, stage, port, project):
        self.stage, self.port, self.project = Path(stage), port, project
        if (self.stage != self.stage.resolve(strict=True) or self.stage.parent not in (Path('/tmp'), Path('/var/tmp'))
                or project != 'nethub-stack-test-' + self.stage.name.lower().replace('.', '-')
                or not re.fullmatch('nethub-stack-test-[a-z0-9-]+', project)):
            raise RecoveryError('Owned recovery source required')
        self.work = self.stage / 'restore-test'
        self.work.mkdir(mode=0o700)
        self.counter = 0
        self.compose = ['docker', 'compose', '-p', project, '-f', str(self.stage / 'deployment/docker-compose.yml'),
                        '-f', str(self.stage / 'deployment/docker-compose.override.yml'), '-f', str(self.stage / 'test.yml')]

    def command(self, args, label, *, data=None, timeout=60):
        self.counter += 1
        try:
            value = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise RecoveryError(label + ' unavailable or timed out') from None
        (self.work / f'step-{self.counter}.log').write_bytes(value.stdout + value.stderr)
        if value.returncode:
            raise RecoveryError(label + ' failed')
        return value.stdout

    def sql(self, query):
        return self.command(['docker', 'exec', '-i', self.postgres, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                             '-U', 'postgres', '-d', 'nethub', '-c', query], 'Quiesced source database read').decode().strip()

    def remote(self, guest, args, label, timeout=60):
        return guest.ssh(shlex.join(args) + '\n', label, timeout=timeout)

    def remote_sql(self, guest, postgres, query):
        return self.remote(guest, ['docker', 'exec', '-i', postgres, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                                  '-U', 'postgres', '-d', 'nethub', '-c', query],
                           'Fresh recovery database read').decode().strip()

    def source_inventory(self):
        ids = self.command(self.compose + ['ps', '-q'], 'Recovery source service inventory').decode().splitlines()
        values = json.loads(self.command(['docker', 'inspect', *ids], 'Recovery source ownership'))
        found = {}
        for value in values:
            labels = value['Config']['Labels']
            name = labels.get('com.docker.compose.service')
            if (labels.get('com.docker.compose.project') != self.project or name not in SERVICES
                    or name in found or value['State']['Running'] is not True):
                raise RecoveryError('Recovery source ownership or state differs')
            found[name] = value
        if set(found) != SERVICES:
            raise RecoveryError('Exactly six original recovery services required')
        self.services = found
        self.postgres = found['postgres']['Id']
        networks = found['caddy']['NetworkSettings']['Networks']
        if len(networks) != 1:
            raise RecoveryError('Recovery source edge is ambiguous')
        self.gateway = str(ipaddress.IPv4Address(next(iter(networks.values()))['Gateway']))
        self.volumes = {}
        for name in VOLUMES:
            mounts = [item for service in found.values() for item in service['Mounts']
                      if item['Type'] == 'volume' and item['Name'] == self.project + '_' + name]
            if len(mounts) != 1:
                raise RecoveryError('Recovery source volume identity differs')
            value = json.loads(self.command(['docker', 'volume', 'inspect', mounts[0]['Name']],
                                           'Recovery source volume ownership'))[0]
            if (value['Labels'].get('com.docker.compose.project') != self.project
                    or value['Mountpoint'] != '/var/lib/docker/volumes/' + self.project + '_' + name + '/_data'):
                raise RecoveryError('Recovery source volume path differs')
            self.volumes[name] = Path(value['Mountpoint'])

    @contextmanager
    def lease(self):
        path = self.stage / 'deployment/relay-operation.lock'
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                or info.st_size != 0 or stat.S_IMODE(info.st_mode) != 0o600):
            raise RecoveryError('Recovery source operation lease is unsafe')
        with path.open('r+b') as lock:
            if os.fstat(lock.fileno()).st_ino != info.st_ino:
                raise RecoveryError('Recovery source lease changed')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def snapshot(self):
        self.command(self.compose + ['run', '--rm', '--no-deps', '-T', 'backup', 'backup', 'run',
                     '--sslmode', 'disable', '--timeout', '60s', '--max-bytes', str(64 * 1024**2)],
                     'Quiesced restricted full database archive', timeout=90)
        state = json.loads((self.volumes['database-backups'] / 'last-run.json').read_text())
        receipt = state['latest_success']
        if (state['outcome'] != 'succeeded' or receipt['role'] != 'nethub_backup'
                or not re.fullmatch('nethub-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}\\.dump', receipt['archive'])):
            raise RecoveryError('Quiesced archive receipt differs')
        self.archive = self.volumes['database-backups'] / receipt['archive']
        if sha256(self.archive) != receipt['sha256'] or self.archive.stat().st_size != receipt['bytes']:
            raise RecoveryError('Quiesced archive integrity differs')
        manifest = json.loads((self.stage / 'deployment/setup.json').read_text())
        selected = [self.stage / 'deployment', self.stage / 'backup', *self.stage.glob('token-successor-*')]
        if Path(manifest['backup_directory']) not in selected or manifest['backup_directory'] == str(self.stage / 'backup'):
            raise RecoveryError('Recovery must retain the current post-rotation independent backup')
        paths = {self.stage}
        for root in [*selected, *self.volumes.values()]:
            paths.add(root)
            paths.update(root.rglob('*'))
        paths.update(self.stage / name for name in ('Caddyfile', 'test.yml', 'http01-nethub'))
        self.payload = self.work / 'current-files.tar'
        self.payload_receipt = pack(paths, self.payload)

    def original_login(self):
        base = ['curl', '--silent', '--show-error', '--fail', '--noproxy', '*', '--max-time', '10',
                '--cacert', str(self.stage / 'console-ca.pem'), '--connect-to',
                f'console.example.com:443:127.0.0.1:{self.port}']
        cookies = self.work / 'restored-cookies'
        value = json.loads(self.command(base + ['-c', str(cookies), '-H', 'Content-Type: application/json',
            '-H', 'Origin: https://console.example.com', '--data-binary', '@' + str(self.stage / 'login.json'),
            'https://console.example.com/api/v1/console/login'], 'Original administrator login on recovered host'))
        original = json.loads((self.stage / 'login-response.json').read_text())
        if value['user']['id'] != original['user']['id'] or value['user']['role'] != 'admin':
            raise RecoveryError('Restored administrator identity differs')
        header = self.work / 'restored-csrf'
        header.write_text('X-CSRF-Token: ' + value['csrf_token'] + '\n')
        inventory = json.loads(self.command(base + ['-b', str(cookies),
            'https://console.example.com/api/v1/console/devices'], 'Restored administrator inventory'))
        self.restored_device_ids = {item['id'] for item in inventory['items']}
        # An explicit Open is normal operator behavior when the private fixture's
        # forwarding topology changes the source IP. It must not renew on access.
        for device in sorted(self.restored_device_ids):
            if re.fullmatch('[a-f0-9-]{36}', device) is None:
                raise RecoveryError('Restored inventory identity differs')
            self.command(base + ['-b', str(cookies), '-H', '@' + str(header), '-H', 'Content-Type: application/json',
                '-H', 'Origin: https://console.example.com', '--data', '{}',
                'https://console.example.com/api/v1/console/devices/' + device + '/open'],
                'Explicit source grant on recovered host')


def exercise(stage, port, project, evidence, native_read, inspect_gui, route, witness_route, witness_process):
    fixture = Restore(stage, port, project)
    result = {'passed': False, 'phase': 'source_preflight', 'full_goal_complete': False,
              'public_network_or_formal_release_acceptance': False, 'off_host_durable_custody': False}
    stopped = False
    target_guest = None
    try:
        fixture.source_inventory()
        before = native_read('native-before-host-restore.json')
        gui = inspect_gui()
        fixture.command([str(fixture.stage / 'http01-nethub'), 'doctor', '--directory',
                         str(fixture.stage / 'deployment')], 'Current key and independent backup preflight')
        image_tags = sorted({value['Config']['Image'] for value in fixture.services.values()})
        image_ids = {value['Config']['Image']: value['Image'] for value in fixture.services.values()}
        images = fixture.work / 'images.tar'
        fixture.command(['docker', 'image', 'save', '-o', str(images), *image_tags], 'Owned tested image export', timeout=180)
        images.chmod(0o600)
        result['phase'] = 'target_prepare'
        target_directory = Path(os.environ['RUNNER_TEMP']) / 'native-recovery-target-private'
        target_guest = LinuxGuest(target_directory)
        with target_guest as target:
            result['target'] = target.prepare()
            target.ssh('umask 077\nmkdir /root/nethub-recovery\n', 'Private empty recovery transfer directory')
            target_images = target.send(images, 'images.tar')
            fixture.remote(target, ['docker', 'load', '-i', target_images], 'Recovery image load', timeout=180)
            for tag, identifier in image_ids.items():
                actual = fixture.remote(target, ['docker', 'image', 'inspect', '--format', '{{.Id}}', tag],
                                        'Recovery image identity').decode().strip()
                if actual != identifier:
                    raise RecoveryError('Recovery images differ from original tested images')
            for name, path in fixture.volumes.items():
                actual = fixture.remote(target, ['docker', 'volume', 'create', '--label',
                    'com.docker.compose.project=' + project, '--label', 'com.docker.compose.volume=' + name,
                    project + '_' + name], 'Empty target volume creation').decode().strip()
                if actual != project + '_' + name:
                    raise RecoveryError('Fresh target volume identity differs')
                observed = fixture.remote(target, ['docker', 'volume', 'inspect', '--format', '{{.Mountpoint}}', actual],
                                          'Fresh target volume path').decode().strip()
                if observed != str(path):
                    raise RecoveryError('Fresh target volume path differs')
            source_stopped_at = time.monotonic()
            with fixture.lease():
                result['phase'] = 'quiesced_snapshot'
                stopped = True
                fixture.command(fixture.compose + ['stop', '--timeout', '10', *WRITERS], 'Source writer quiescence', timeout=75)
                original_database = fingerprint(fixture.sql)
                original_system = fixture.sql('SELECT system_identifier FROM pg_control_system();')
                fixture.snapshot()
                if fingerprint(fixture.sql) != original_database:
                    raise RecoveryError('Source database changed during quiesced backup')
                fixture.command(fixture.compose + ['stop', '--timeout', '10', 'postgres'], 'Original database shutdown', timeout=30)
                if fixture.command(fixture.compose + ['ps', '-q'], 'Source shutdown proof').strip():
                    raise RecoveryError('Original recovery services remain running')
                result['phase'] = 'files_restore'
                remote_payload = target.send(fixture.payload, 'current-files.tar')
                extractor = fixture.work / 'payload.py'
                extractor.write_bytes(Path(__file__).with_name('payload.py').read_bytes())
                extractor.chmod(0o600)
                remote_extractor = target.send(extractor, 'payload.py')
                receipt = fixture.payload_receipt
                restored = json.loads(fixture.remote(target, ['python3', remote_extractor, remote_payload,
                    receipt['sha256'], receipt['inventory_sha256'], str(fixture.stage),
                    *map(str, fixture.volumes.values())], 'Private current-key and stopped-volume recovery'))
                if restored != {'files_restored': True, 'inventory_verified': True, 'entries': receipt['entries']}:
                    raise RecoveryError('Recovered file inventory differs')
                fixture.remote(target, [str(fixture.stage / 'http01-nethub'), 'doctor', '--directory',
                    str(fixture.stage / 'deployment')], 'Recovered current keys and independent backup')
                result['phase'] = 'database_restore'
                fixture.remote(target, fixture.compose + ['up', '-d', '--no-build', '--pull', 'never',
                    '--wait', '--wait-timeout', '90', 'postgres'], 'Fresh PostgreSQL role bootstrap', timeout=120)
                target_postgres = fixture.remote(target, fixture.compose + ['ps', '-q', 'postgres'],
                                                  'Fresh PostgreSQL container identity').decode().strip()
                if not re.fullmatch('[a-f0-9]{64}', target_postgres) or target_postgres == fixture.postgres:
                    raise RecoveryError('Fresh PostgreSQL container identity differs')
                sql = lambda query: fixture.remote_sql(target, target_postgres, query)
                if (sql("SELECT count(*) FROM pg_tables WHERE schemaname='public';") != '0'
                        or sql('SELECT system_identifier FROM pg_control_system();') == original_system):
                    raise RecoveryError('Recovery requires a distinct empty PostgreSQL cluster')
                fixture.remote(target, ['docker', 'cp', str(fixture.archive), target_postgres + ':/tmp/recovery.dump'],
                               'Private full archive staging')
                fixture.remote(target, ['docker', 'exec', '--user', '0', target_postgres,
                    'chown', '70:70', '/tmp/recovery.dump'], 'Private database archive ownership')
                fixture.remote(target, ['docker', 'exec', '-i', '--user', 'postgres', target_postgres,
                    'pg_restore', '--exit-on-error', '--single-transaction', '-U', 'postgres', '-d', 'nethub',
                    '/tmp/recovery.dump'], 'Full schema ownership and ACL recovery', timeout=120)
                if fingerprint(sql) != original_database:
                    raise RecoveryError('Restored database contents or role grants differ')
                result['phase'] = 'services_restore'
                fixture.remote(target, fixture.compose + ['up', '-d', '--no-build', '--pull', 'never',
                    '--wait', '--wait-timeout', '120'], 'Recovered six-service startup', timeout=150)
                remote_ids = fixture.remote(target, fixture.compose + ['ps', '-q'], 'Recovered six-service inventory').decode().splitlines()
                if len(remote_ids) != 6 or any(value in {v['Id'] for v in fixture.services.values()} for value in remote_ids):
                    raise RecoveryError('Recovered service inventory is not distinct')
                for mode in ('--database-roles', '--audit'):
                    fixture.remote(target, fixture.compose + ['exec', '-T', 'nethub-web', '/nethub', 'doctor', mode,
                        '--password-file', '/run/secrets/pg_nethub_web', '--sslmode', 'disable'], 'Recovered read-only database readiness')
                fixture.remote(target, [str(fixture.stage / 'http01-nethub'), 'doctor', '--runtime-containers',
                    '--directory', str(fixture.stage / 'deployment'), '--project', project,
                    '--compose-file', str(fixture.stage / 'test.yml')], 'Recovered service separation')
                result['phase'] = 'automatic_native_reconnection'
                with target.forward([('127.0.0.1', port, '127.0.0.1', port),
                                     ('127.0.0.1', 7000, '127.0.0.1', 7000)]):
                    fixture.original_login()
                    if before['device_id'] not in fixture.restored_device_ids:
                        raise RecoveryError('Original device missing after full host recovery')
                    granted = sql("SELECT host(source_ip) FROM device_access_grants WHERE device_id='" +
                                  before['device_id'] + "' ORDER BY expires_at DESC,source_ip DESC LIMIT 1;")
                    addresses = json.loads(fixture.remote(target, ['ip', '-j', 'addr'], 'Recovered host source ownership'))
                    owned = {item['local'] for interface in addresses for item in interface['addr_info']}
                    # Forward to the actual source admitted by normal Open, without
                    # inserting fixture-only SQL grants into the recovered database.
                    if str(ipaddress.IPv4Address(granted)) not in owned:
                        raise RecoveryError('Recovered Open source is not owned by the target host')
                    with target.forward([(fixture.gateway, 8443, granted, 8443)]):
                        deadline = time.monotonic() + 90
                        while not (route() and witness_route()):
                            if time.monotonic() >= deadline or witness_process.poll() is not None:
                                raise RecoveryError('Retained native and witness routes did not reconnect')
                            time.sleep(1)
                        if native_read('native-after-host-restore.json') != before or inspect_gui() != gui:
                            raise RecoveryError('Host recovery altered native assignment or GUI identity')
                        result['source_stop_to_verified_native_and_witness_routes_ms'] = round((time.monotonic() - source_stopped_at) * 1000)
                        if fixture.command(fixture.compose + ['ps', '-q'], 'Original services remain stopped').strip():
                            raise RecoveryError('Original services restarted during target recovery')
                        result.update(current_keys_matching_independent_backup_and_operation_history_restored=True,
                            all_database_tables_sequences_ownership_ACLs_and_roles_restored=True,
                            distinct_new_PostgreSQL_cluster=True, same_tested_images_and_six_new_services=True,
                            original_administrator_login_and_inventory=True, explicit_Open_on_recovered_host=True,
                            original_native_model_GUI_key_checks_and_alias_unchanged=True,
                            retained_native_and_witness_verified_TLS_routes_automatically_reconnected=True,
                            no_native_restart_rotate_or_reenrollment_command=True, original_six_services_stayed_stopped=True)
                result['phase'] = 'target_cleanup'
                fixture.remote(target, fixture.compose + ['down', '-v', '--remove-orphans'], 'Owned restored stack cleanup', timeout=90)
                if fixture.remote(target, ['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project],
                                  'Owned restored stack absence').strip():
                    raise RecoveryError('Restored target cleanup incomplete')
            result['restored_target_stack_removed'] = True
        result['owned_recovery_guest_stopped'] = target.process.poll() is not None
        result['phase'] = 'source_fixture_recovery'
    finally:
        if target_guest is not None and target_guest.process is not None:
            result['owned_recovery_guest_stopped'] = target_guest.process.poll() is not None
        try:
            if stopped:
                fixture.command(fixture.compose + ['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '120'],
                                'Original fixture service recovery for subsequent cleanup', timeout=150)
                result['original_fixture_services_recovered_for_remaining_tail'] = True
        finally:
            (Path(evidence) / 'installed-host-restore.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    deadline = time.monotonic() + 60
    while not (route() and witness_route()):
        if time.monotonic() >= deadline or witness_process.poll() is not None:
            raise RecoveryError('Original fixture routes did not recover before normal cleanup')
        time.sleep(1)
    if native_read('native-after-source-return.json') != before or inspect_gui() != gui:
        raise RecoveryError('Source fixture return altered native policy')
    result.update(passed=True, phase='complete', original_fixture_routes_verified_before_normal_native_removal=True)
    (Path(evidence) / 'installed-host-restore.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result
