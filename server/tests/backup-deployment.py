"""Exercise the real backup image against nonce-owned databases and storage."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import uuid
from datetime import datetime, timedelta, timezone


class Failure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


class Acceptance:
    def __init__(self, stage, project, runtime, backup, postgres):
        require(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Linux root fixture required')
        self.stage = Path(stage).absolute()
        require(self.stage.resolve(strict=True) == self.stage and self.stage.parent in (Path('/tmp'), Path('/var/tmp')), 'private stage location')
        require(self.stage.stat().st_uid == 0 and stat.S_IMODE(self.stage.stat().st_mode) == 0o700, 'private stage ownership')
        require(re.fullmatch(r'nethub-stack-test-[a-z0-9-]+', project), 'owned project format')
        require(project == 'nethub-stack-test-' + self.stage.name.lower().replace('.', '-'), 'owned project identity')
        require(re.fullmatch(r'[a-f0-9]{64}', postgres), 'owned PostgreSQL identity')
        self.project, self.runtime, self.backup, self.postgres = project, runtime, backup, postgres
        self.work = self.stage / 'backup-acceptance'
        self.work.mkdir(mode=0o700)
        self.nonce = secrets.token_hex(8)
        self.volume = project + '-backup-' + self.nonce
        self.database = 'nethub_backup_' + self.nonce
        self.restored = 'nethub_restore_' + self.nonce
        self.databases = []
        self.containers = set()
        self.volume_created = False
        self.counter = 0
        self.copy_path = '/tmp/nethub-backup-' + self.nonce + '.dump'
        self.copy_created = False
        self.lock_process = None
        self.lock_application = 'nethub-backup-lock-' + self.nonce
        pg = self.inspect('container', postgres)
        require(pg and pg['State']['Running'], 'running owned PostgreSQL required')
        require(pg['Config']['Labels'].get('com.docker.compose.project') == project and pg['Config']['Labels'].get('org.nethub.gui-issuer-test') == project, 'PostgreSQL ownership labels')
        self.backup_id = self.inspect('image', backup)['Id']

    def command(self, arguments, check=True, timeout=45, data=None, log=True):
        self.counter += 1
        result = subprocess.run(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', *arguments], input=data, capture_output=True, timeout=timeout)
        if log:
            (self.work / ('step-' + str(self.counter) + '.log')).write_bytes(result.stdout + result.stderr)
        if check and result.returncode:
            raise Failure('backup fixture command failed at step ' + str(self.counter) + '; diagnostic retained privately')
        return result

    def inspect(self, kind, name):
        result = self.command([kind, 'inspect', name], check=False)
        if result.returncode:
            self.command(['info', '--format', '{{.ID}}'])
            require(b'no such' in result.stderr.lower() or b'not found' in result.stderr.lower(), 'resource absence not established')
            return None
        values = json.loads(result.stdout)
        require(len(values) == 1, 'resource identity count')
        return values[0]

    def sql(self, database, query, check=True):
        return self.command(['exec', '--user', 'postgres', self.postgres, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', database], check=check, data=query.encode())

    def create_database(self, name):
        self.sql('postgres', 'CREATE DATABASE ' + name + ' OWNER nethub_owner;\n')
        self.databases.append(name)
        self.sql('postgres', 'REVOKE ALL ON DATABASE ' + name + ' FROM PUBLIC; GRANT CONNECT ON DATABASE ' + name + ' TO nethub_owner,nethub_backup,nethub_web;\n')

    def owned_container(self, name):
        require(self.inspect('container', name) is None, 'refusing existing container')
        self.containers.add(name)
        return ['--name', name, '--label', 'org.nethub.backup-test=' + self.nonce]

    def container_options(self, name):
        secret = self.stage / 'deployment/secrets/backup'
        require(secret.resolve(strict=True) == secret and ',' not in str(secret), 'backup secret source')
        return [*self.owned_container(name), '--network', self.project + '_database', '--read-only', '--user', '65532:65532', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--mount', 'type=bind,source=' + str(secret) + ',target=/run/secrets,readonly',
                '--mount', 'type=volume,source=' + self.volume + ',target=/var/lib/nethub-backups',
                '--tmpfs', '/run/nethub-backup:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=65532,gid=65532']

    def backup_command(self, action='run', extra=(), expected=0):
        name = self.project + '-backup-once-' + secrets.token_hex(4)
        result = self.command(['run', '--rm', *self.container_options(name), self.backup, 'backup', action, '--database', self.database, '--sslmode', 'disable', '--timeout', '30s', '--max-bytes', str(64 << 20), *extra], check=False, timeout=45)
        require(result.returncode == expected, 'compiled backup returned unexpected status')
        return result

    def receipt(self):
        directory = self.archive_root.lstat()
        require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 65532 and stat.S_IMODE(directory.st_mode) == 0o700, 'private populated archive volume')
        state_path = self.archive_root / 'last-run.json'
        info = state_path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 65532 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 8192, 'private attempt state')
        state = json.loads(state_path.read_text(encoding='utf-8'))
        receipt = state['latest_success']
        require(re.fullmatch(r'nethub-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}\.dump', receipt['archive']), 'managed archive name')
        path = self.archive_root / receipt['archive']
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 65532 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == receipt['bytes'], 'private custom archive')
        with path.open('rb') as file:
            require(file.read(5) == b'PGDMP', 'custom archive header')
            file.seek(0)
            require(hashlib.file_digest(file, 'sha256').hexdigest() == receipt['sha256'], 'complete archive hash')
        require(receipt['role'] == 'nethub_backup' and receipt['dump_version'].startswith('16.'), 'actual restricted producer')
        require(state['deployment_fingerprint'] == self.fingerprint, 'database-derived archive binding')
        return state, path

    def deep_doctor(self, expected=0):
        name = self.project + '-backup-doctor-' + secrets.token_hex(4)
        result = self.command(['run', '--rm', *self.container_options(name), self.backup, 'doctor', '--recent-backup', '--backup-directory', '/var/lib/nethub-backups', '--host', 'postgres', '--database', self.database, '--password-file', '/run/secrets/pg_nethub_backup', '--sslmode', 'disable', '--backup-timeout', '30s'], check=False)
        require(result.returncode == expected, 'compiled deep backup doctor status')
        if expected == 0:
            require(b'Recent database archive integrity and freshness passed' in result.stdout, 'deep doctor omitted full verification scope')

    def image_profile(self):
        image = self.inspect('image', self.backup)
        require(image['Config']['User'] == '65532:65532' and not image['Config'].get('Volumes') and not image['Config'].get('ExposedPorts'), 'client-only image metadata')
        probe = self.project + '-backup-image-' + self.nonce
        self.command(['create', *self.owned_container(probe), '--network', 'none', self.backup, 'version'])
        archive = self.work / 'image-rootfs.tar'
        self.command(['export', '--output', str(archive), probe])
        with tarfile.open(archive) as source:
            entries = {item.name.removeprefix('./').rstrip('/'): item for item in source.getmembers()}
            for name in ('var/lib/nethub-backups', 'run/nethub-backup'):
                info = entries[name]
                require(info.isdir() and info.uid == 65532 and info.gid == 65532 and info.mode & 0o777 == 0o700, 'private image storage directory')
            for name in ('usr/local/bin/pg_dump', 'usr/local/bin/pg_restore', 'nethub'):
                require(entries[name].isfile() and entries[name].mode & 0o111, 'actual executable client tool')
            require(not {'usr/local/bin/postgres', 'usr/local/bin/gosu', 'bin/sh', 'docker-entrypoint.sh', 'var/lib/postgresql/data'} & set(entries), 'unexpected server/helper/rootfs content')
        archive.unlink()
        result = self.command(['run', '--rm', '--network', 'none', '--user', '65532:65532', '--entrypoint', '/usr/local/bin/pg_dump', self.backup, '--version'])
        require(re.fullmatch(rb'pg_dump \(PostgreSQL\) 16\.[0-9]+\n', result.stdout), 'real nonroot PostgreSQL client execution')

    def prepare(self):
        self.image_profile()
        self.create_database(self.database)
        secret = self.stage / 'deployment/secrets/migrate'
        name = self.project + '-backup-migrate-' + self.nonce
        self.command(['run', '--rm', *self.owned_container(name), '--network', self.project + '_database', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--mount', 'type=bind,source=' + str(secret) + ',target=/run/secrets,readonly', self.runtime, 'migrate', '--host', 'postgres', '--database', self.database, '--password-file', '/run/secrets/pg_nethub_owner', '--sslmode', 'disable'])
        tenant = self.sql(self.database, 'SELECT id FROM tenants;\n').stdout.decode().strip()
        require(str(uuid.UUID(tenant)) == tenant, 'sole fixture tenant')
        self.tenant = tenant
        self.fingerprint = hashlib.sha256(('nethub-database-backup-v1\0' + tenant).encode()).hexdigest()
        owner = self.sql(self.database, "INSERT INTO users(tenant_id,email,role,password_hash) VALUES('" + tenant + "','backup-fixture@example.test','admin','fixture-only-hash') RETURNING id;\n").stdout.decode().strip()
        require(str(uuid.UUID(owner)) == owner, 'fixture owner identity')
        self.sql(self.database, "INSERT INTO devices(tenant_id,owner_user_id,platform,device_secret_hash,subdomain,agent_protocol_version) VALUES('" + tenant + "','" + owner + "','opnsense','fixture-only-hash','backup-" + self.nonce + "','1.0.0');\n")
        self.digest_query = "SELECT md5(COALESCE(string_agg(row_to_json(d)::text,E'\\n' ORDER BY d.id),'')) FROM devices d;\n"
        self.source_digest = self.sql(self.database, self.digest_query).stdout.decode().strip()
        require(self.inspect('volume', self.volume) is None, 'refusing existing backup volume')
        self.command(['volume', 'create', '--label', 'org.nethub.backup-test=' + self.nonce, self.volume])
        self.volume_created = True
        volume = self.inspect('volume', self.volume)
        require(volume['Name'] == self.volume and volume['Driver'] == 'local' and not volume.get('Options') and volume['Labels'].get('org.nethub.backup-test') == self.nonce, 'owned local volume')
        self.archive_root = Path(volume['Mountpoint'])
        require(self.archive_root.is_absolute() and self.archive_root.resolve(strict=True) == self.archive_root, 'local archive mountpoint')

    def restore(self, path):
        self.create_database(self.restored)
        self.command(['cp', str(path), self.postgres + ':' + self.copy_path])
        self.copy_created = True
        self.command(['exec', '--user', '0', self.postgres, 'chown', '70:70', self.copy_path])
        self.command(['exec', '--user', 'postgres', self.postgres, 'pg_restore', '--exit-on-error', '--username', 'postgres', '--dbname', self.restored, self.copy_path])
        require(self.sql(self.restored, self.digest_query).stdout.decode().strip() == self.source_digest, 'restored actual device content')
        allowed = self.sql(self.restored, "SET SESSION AUTHORIZATION nethub_web; SELECT set_config('app.tenant_id','" + self.tenant + "',false); SELECT count(id) FROM devices;\n")
        require(allowed.stdout.decode().strip().splitlines()[-1] == '1', 'restored Web safe-column visibility')
        denied = self.sql(self.restored, "\\set VERBOSITY sqlstate\nSET SESSION AUTHORIZATION nethub_web; SELECT device_secret_hash FROM devices;\n", check=False)
        require(denied.returncode != 0 and b'42501' in denied.stderr, 'restored Web credential-column refusal')

    def failure_and_retention(self):
        before, _ = self.receipt()
        good = before['latest_success']
        self.sql(self.database, 'GRANT UPDATE(label) ON devices TO nethub_backup;\n')
        self.backup_command(expected=1)
        failed, _ = self.receipt()
        require(failed['outcome'] == 'failed' and failed['latest_success'] == good, 'preflight failure retained last good archive')
        self.sql(self.database, 'REVOKE UPDATE(label) ON devices FROM nethub_backup;\n')
        self.deep_doctor(expected=1)
        self.backup_command()
        recovered, source = self.receipt()
        require(recovered['outcome'] == 'succeeded' and recovered['latest_success']['archive'] != good['archive'], 'actual preflight recovery')
        require(recovered['latest_success']['bytes'] > 1024, 'size-failure fixture archive size')
        self.backup_command(extra=('--max-bytes', '1024'), expected=1)
        failed, _ = self.receipt()
        require(failed['outcome'] == 'failed' and failed['latest_success'] == recovered['latest_success'], 'actual pg_dump size failure retained last good')
        self.backup_command()
        _, source = self.receipt()
        old = datetime.now(timezone.utc) - timedelta(days=40)
        expired = self.archive_root / ('nethub-' + old.strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(8) + '.dump')
        shutil.copyfile(source, expired)
        os.chown(expired, 65532, 65532)
        expired.chmod(0o600)
        os.utime(expired, (old.timestamp(), old.timestamp()))
        unmanaged = self.archive_root / 'operator-retained.txt'
        unmanaged.write_text('retained fixture\n', encoding='utf-8')
        os.chown(unmanaged, 65532, 65532)
        unmanaged.chmod(0o600)
        unsafe = self.archive_root / ('nethub-' + old.strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(8) + '.dump')
        unsafe.symlink_to(source.name)
        self.backup_command(expected=1)
        require(expired.exists() and unsafe.is_symlink(), 'unsafe retention must refuse before deleting expired candidates')
        failed, _ = self.receipt()
        require(failed['outcome'] == 'failed', 'retention failure must not report a completed cycle')
        unsafe.unlink()
        fresh = self.archive_root / ('nethub-' + old.strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(8) + '.dump')
        shutil.copyfile(source, fresh)
        os.chown(fresh, 65532, 65532)
        fresh.chmod(0o600)
        self.backup_command()
        require(not expired.exists() and fresh.exists() and unmanaged.read_text(encoding='utf-8') == 'retained fixture\n', 'actual retention, fresh-copy and unmanaged-file preservation')
        self.deep_doctor()
        _, source = self.receipt()
        original = source.read_bytes()
        changed = bytearray(original)
        changed[-1] ^= 1
        source.write_bytes(changed)
        self.deep_doctor(expected=1)
        source.write_bytes(original)
        self.deep_doctor()

    def wait_healthy(self, container):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            status = self.inspect('container', container)
            require(status and status['State']['Running'], 'backup daemon stopped unexpectedly')
            result = self.command(['exec', container, '/nethub', 'backup', 'health'], check=False, timeout=15)
            if result.returncode == 0 and status['State'].get('Health', {}).get('Status') == 'healthy':
                return
            time.sleep(0.5)
        raise Failure('real backup daemon did not become healthy')

    def daemon(self):
        name = self.project + '-backup-daemon-' + self.nonce
        self.command(['run', '-d', *self.container_options(name), self.backup, 'backup', 'serve', '--database', self.database, '--sslmode', 'disable', '--timeout', '30s', '--max-bytes', str(64 << 20)])
        self.wait_healthy(name)
        before, _ = self.receipt()
        self.command(['restart', name], timeout=45)
        self.wait_healthy(name)
        after, _ = self.receipt()
        require(before['latest_success']['archive'] != after['latest_success']['archive'], 'restarted daemon did not perform a fresh cycle')
        runtime = self.command(['cp', name + ':/run/nethub-backup/.', '-'], log=False).stdout
        with tarfile.open(fileobj=io.BytesIO(runtime)) as archive:
            files = [item for item in archive.getmembers() if not item.isdir()]
            require({Path(item.name).name for item in files} == {'worker-health.json', '.nethub-backup-runtime.lock'} and len(files) == 2, 'temporary passfiles remained after real cycle')
            require(all(item.isfile() and item.uid == 65532 and item.mode & 0o777 == 0o600 for item in files), 'private runtime metadata')
        self.command(['stop', '--time', '10', name], timeout=20)
        stopped = self.inspect('container', name)
        require(not stopped['State']['Running'] and stopped['State']['ExitCode'] == 0, 'signal-aware daemon shutdown')
        self.deep_doctor()
        self.interrupted_dump(name)

    def interrupted_dump(self, name):
        before, _ = self.receipt()
        query = "SET application_name='" + self.lock_application + "'; BEGIN; LOCK TABLE devices IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(90); ROLLBACK;\n"
        self.lock_process = subprocess.Popen(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', 'exec', '--user', 'postgres', self.postgres, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', self.database, '-c', query], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            ready = self.sql(self.database, "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name='" + self.lock_application + "' AND l.mode='AccessExclusiveLock' AND l.granted;\n")
            if ready.stdout.strip() == b'1':
                break
            require(self.lock_process.poll() is None, 'fixture lock process exited early')
            time.sleep(0.2)
        else:
            raise Failure('fixture database lock was not acquired')
        self.command(['start', name])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            waiting = self.sql(self.database, "SELECT count(*) FROM pg_stat_activity WHERE datname='" + self.database + "' AND usename='nethub_backup' AND application_name='pg_dump' AND wait_event_type='Lock';\n")
            if waiting.stdout.strip() == b'1':
                break
            time.sleep(0.2)
        else:
            raise Failure('actual pg_dump did not reach the controlled database wait')
        started = time.monotonic()
        self.command(['stop', '--time', '10', name], timeout=15)
        stopped = self.inspect('container', name)
        require(time.monotonic() - started < 10 and not stopped['State']['Running'] and stopped['State']['ExitCode'] == 0, 'active dump shutdown exceeded its grace period')
        failed, _ = self.receipt()
        require(failed['outcome'] == 'failed' and failed['latest_success'] == before['latest_success'], 'cancelled real dump retained the previous successful archive')
        require(not any(path.name.startswith('.partial-') for path in self.archive_root.iterdir()), 'cancelled dump left a partial archive')
        self.release_database_lock()
        self.deep_doctor(expected=1)
        self.command(['start', name])
        self.wait_healthy(name)
        self.command(['stop', '--time', '10', name], timeout=15)
        self.deep_doctor()

    def release_database_lock(self):
        if self.lock_process is not None:
            self.sql(self.database, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='" + self.database + "' AND application_name='" + self.lock_application + "' AND usename='postgres';\n")
            self.lock_process.wait(timeout=10)
            self.lock_process = None

    def cleanup(self):
        self.release_database_lock()
        for name in sorted(self.containers):
            value = self.inspect('container', name)
            if value is not None:
                require(value['Config']['Labels'].get('org.nethub.backup-test') == self.nonce, 'container cleanup ownership changed')
                self.command(['rm', '-f', value['Id']])
        if self.copy_created:
            self.command(['exec', '--user', '0', self.postgres, 'rm', '--', self.copy_path])
        for database in reversed(self.databases):
            self.sql('postgres', 'DROP DATABASE ' + database + ' WITH (FORCE);\n')
        if self.volume_created:
            volume = self.inspect('volume', self.volume)
            require(volume and volume['Labels'].get('org.nethub.backup-test') == self.nonce, 'volume cleanup ownership changed')
            self.command(['volume', 'rm', self.volume])


def main():
    require(len(sys.argv) == 6, 'stage, project, runtime, backup image and PostgreSQL identity required')
    suite = Acceptance(*sys.argv[1:])
    passed = False
    try:
        suite.prepare()
        suite.backup_command()
        state, path = suite.receipt()
        require(state['outcome'] == 'succeeded', 'actual archive publication')
        suite.deep_doctor()
        suite.restore(path)
        suite.failure_and_retention()
        suite.daemon()
        passed = True
    finally:
        suite.cleanup()
    require(passed, 'backup acceptance did not complete')
    print('Actual nonroot backup image passed restricted dump, full doctor, restore/content and Web-column boundaries, preflight/size failures, last-good recovery, retention, corruption refusal, daemon restart/shutdown and owned cleanup')


if __name__ == '__main__':
    try:
        main()
    except (Failure, subprocess.SubprocessError, OSError, ValueError, KeyError) as error:
        # Failure contains only fixed fixture messages and numeric step counters.
        # Dependency exception text can contain private responses or paths.
        detail = str(error) if isinstance(error, Failure) else type(error).__name__
        print('Backup deployment acceptance failed; private fixture diagnostics retained: ' + detail, file=sys.stderr)
        raise SystemExit(1)
