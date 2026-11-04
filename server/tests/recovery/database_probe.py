"""Compare real restore modes on an owned hosted PostgreSQL migration fixture."""
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

from database import bootstrap_extensions, capture, difference_details, differing_categories, snapshot_fingerprint
from database_controls import check


class Probe:
    def __init__(self, root, directory):
        self.root, self.directory = root, directory
        self.nonce = secrets.token_hex(12)
        self.name = 'nethub-recovery-probe-' + self.nonce
        self.image = self.name + ':postgres'
        self.label = 'org.nethub.recovery-probe'
        self.steps = 0
        self.created = False
        self.built = False

    def command(self, arguments, data=None, check=True, timeout=90):
        self.steps += 1
        result = subprocess.run(['docker', *arguments], input=data, capture_output=True, timeout=timeout)
        (self.directory / ('step-' + str(self.steps) + '.log')).write_bytes(result.stdout + result.stderr)
        if check and result.returncode:
            raise ValueError('Owned database probe command failed')
        return result

    def sql(self, database, query):
        return self.command(['exec', '-i', '-u', 'postgres', self.name, 'psql', '-X', '-qAt',
                             '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', database],
                            data=query.encode()).stdout.decode().strip()

    def prepare(self):
        self.command(['build', '--label', self.label + '=' + self.nonce, '-t', self.image,
                      '-f', str(self.root / 'deploy/images/postgres/Dockerfile'), str(self.root)], timeout=600)
        self.built = True
        secret = self.directory / 'secrets'
        secret.mkdir(mode=0o700)
        for role in ('bootstrap', 'nethub_owner', 'nethub_web', 'nethub_authz', 'nethub_backup'):
            path = secret / ('pg_' + role)
            path.write_text(secrets.token_hex(32) + '\n')
            path.chmod(0o600)
        self.command(['create', '--name', self.name, '--label', self.label + '=' + self.nonce,
                      '--network', 'none', '--entrypoint', '/bin/sh', '-e', 'POSTGRES_USER=postgres',
                      '-e', 'POSTGRES_PASSWORD_FILE=/run/secrets/pg_bootstrap',
                      '-e', 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256', self.image,
                      '/tmp/start-postgres.sh'])
        self.created = True
        self.command(['cp', str(secret), self.name + ':/run/secrets'])
        for source, target in (('deploy/postgres/00-nethub-roles.sh', '/docker-entrypoint-initdb.d/00-nethub-roles.sh'),
                               ('server/tests/start-postgres.sh', '/tmp/start-postgres.sh')):
            self.command(['cp', str(self.root / source), self.name + ':' + target])
        self.command(['start', self.name])
        for _ in range(60):
            ready = self.command(['exec', '-u', 'postgres', self.name, 'psql', '-X', '-qAt',
                                  '-d', 'nethub', '-c', "SELECT count(*) FROM pg_roles WHERE rolname='nethub_backup';"],
                                 check=False)
            if ready.returncode == 0 and ready.stdout.strip() == b'1':
                break
            time.sleep(1)
        else:
            raise ValueError('Owned database bootstrap did not become ready')
        migrations = sorted((self.root / 'server/internal/store/migrations').glob('*.sql'))
        if not migrations:
            raise ValueError('Migration inventory missing')
        # Apply the actual Up DDL as its normal owner, including function bodies.
        # This focused probe does not impersonate a full migrated application.
        for path in migrations:
            text = path.read_text(encoding='utf-8')
            if not text.startswith('-- +goose Up') or text.count('-- +goose Down') != 1:
                raise ValueError('Unexpected migration boundary')
            self.sql('nethub', 'SET SESSION AUTHORIZATION nethub_owner;\n' + text.split('-- +goose Down')[0])
        return len(migrations)

    def exercise(self):
        count = self.prepare()
        controls = check(lambda query: self.sql('nethub', query))
        original = capture(lambda query: self.sql('nethub', query))
        self.command(['exec', '-u', 'postgres', self.name, 'pg_dump', '--format=custom',
                      '--no-password', '-U', 'nethub_backup', '-d', 'nethub', '-f', '/tmp/recovery-probe.dump'])
        if differing_categories(original, capture(lambda query: self.sql('nethub', query))):
            raise ValueError('Owned source changed during dump')
        result = {}
        for mode in ('default', 'session_authorization', 'precreated_extension'):
            database = 'nethub_probe_' + mode
            self.sql('postgres', 'CREATE DATABASE ' + database + ' OWNER nethub_owner;')
            self.sql('postgres', 'REVOKE ALL ON DATABASE ' + database + ' FROM PUBLIC; GRANT CONNECT ON DATABASE '
                     + database + ' TO nethub_owner,nethub_web,nethub_authz,nethub_backup;')
            if mode == 'precreated_extension':
                bootstrap_extensions(lambda query: self.sql(database, query), original)
            options = ['--use-set-session-authorization'] if mode == 'session_authorization' else []
            restored = self.command(['exec', '-u', 'postgres', self.name, 'pg_restore', '--exit-on-error',
                          '--single-transaction', *options, '-U', 'postgres', '-d', database, '/tmp/recovery-probe.dump'],
                          check=False)
            if restored.returncode:
                result[mode] = {'restore_completed': False}
                continue
            expected = []
            for entry in original:
                if entry[0] == 'database':
                    prefix = '["nethub",'
                    if not entry[1].startswith(prefix):
                        raise ValueError('Unexpected source database identity')
                    entry = ('database', '[' + json.dumps(database) + ',' + entry[1][len(prefix):])
                expected.append(entry)
            actual = capture(lambda query: self.sql(database, query))
            refused_conflict = False
            if mode != 'precreated_extension':
                try:
                    bootstrap_extensions(lambda query: self.sql(database, query), original)
                except ValueError:
                    refused_conflict = True
                if (not refused_conflict or snapshot_fingerprint(actual)
                        != snapshot_fingerprint(capture(lambda query: self.sql(database, query)))):
                    raise ValueError('Existing extension conflict was not preserved')
            else:
                bootstrap_extensions(lambda query: self.sql(database, query), original)
                if snapshot_fingerprint(actual) != snapshot_fingerprint(capture(lambda query: self.sql(database, query))):
                    raise ValueError('Approved extension retry changed database authority')
            result[mode] = {'restore_completed': True,
                            'different_categories': differing_categories(expected, actual),
                            'details': difference_details(expected, actual),
                            'conflicting_extension_refused_without_mutation': refused_conflict}
        return {'version': 1, 'source_head': os.environ['NETHUB_SOURCE_HEAD'],
                'migration_ddl_files': count, 'modes': result, 'negative_controls': controls,
                'scope': 'Hosted real migration DDL and PostgreSQL restore diagnosis',
                'complete_application_restore_accepted': False, 'full_goal_complete': False}

    def cleanup(self):
        if self.created:
            value = json.loads(self.command(['inspect', self.name]).stdout)[0]
            if value['Config']['Labels'].get(self.label) != self.nonce:
                raise ValueError('Owned probe container identity differs')
            self.command(['rm', '-f', '-v', self.name])
        if self.built:
            value = json.loads(self.command(['image', 'inspect', self.image]).stdout)[0]
            if value['Config']['Labels'].get(self.label) != self.nonce:
                raise ValueError('Owned probe image identity differs')
            self.command(['image', 'rm', self.image])


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or not hasattr(os, 'geteuid') or os.geteuid() != 0 or len(sys.argv) != 2
            or re.fullmatch('[a-f0-9]{40}', os.environ.get('NETHUB_SOURCE_HEAD', '')) is None):
        raise SystemExit('Fresh hosted root fixture and one result path required')
    destination = Path(sys.argv[1])
    if destination.exists() or destination.is_symlink():
        raise SystemExit('New result path required')
    with tempfile.TemporaryDirectory(prefix='nethub-database-probe-') as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        probe = Probe(Path(__file__).resolve().parents[3], directory)
        try:
            result = probe.exercise()
        finally:
            probe.cleanup()
        result['owned_cleanup_verified'] = True
        destination.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('Owned database diagnosis failed; no private child output exported') from None
