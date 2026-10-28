"""Report bounded backup failure categories without publishing service output."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def docker(*arguments):
    result = subprocess.run(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', *arguments], capture_output=True, timeout=8)
    if result.returncode:
        raise RuntimeError('diagnostic request failed')
    return result.stdout


def main():
    if len(sys.argv) != 4 or os.geteuid() != 0:
        raise ValueError('private Linux fixture required')
    stage, project, image = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    if stage.resolve(strict=True) != stage or stage.parent not in (Path('/tmp'), Path('/var/tmp')) or stage.stat().st_uid != 0 or stat.S_IMODE(stage.stat().st_mode) != 0o700:
        raise ValueError('private stage required')
    if project != 'nethub-stack-test-' + stage.name.lower().replace('.', '-') or not re.fullmatch(r'nethub-stack-test-[a-z0-9-]+', project):
        raise ValueError('owned project required')
    identities = docker('ps', '--all', '--quiet', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + project, '--filter', 'label=com.docker.compose.service=backup').decode().splitlines()
    if not identities:
        print('Backup diagnostic: owned service has not been created')
        return
    if len(identities) != 1 or not re.fullmatch(r'[a-f0-9]{64}', identities[0]):
        raise ValueError('single owned backup required')
    service = json.loads(docker('inspect', '--type', 'container', identities[0]))[0]
    expected = json.loads(docker('image', 'inspect', image))[0]['Id']
    if service['Image'] != expected or service['Config']['Labels'].get('com.docker.compose.project') != project or service['Config']['Labels'].get('com.docker.compose.service') != 'backup':
        raise ValueError('backup identity changed')
    # Docker sends container stderr through its own stderr stream. Capture it
    # privately too; publish only exact application-owned diagnostic categories.
    result = subprocess.run(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', 'logs', '--tail', '20', identities[0]], capture_output=True, timeout=8)
    if result.returncode:
        raise RuntimeError('backup log request failed')
    output = result.stdout + result.stderr
    (stage / 'backup-service-private.log').write_bytes(output)
    (stage / 'backup-service-private.log').chmod(0o600)
    categories = {
        'Backup is already running; let the current operation finish before retrying': 'busy',
        'Backup storage is unavailable; restore private owned directories and the backup password file': 'storage',
        'Backup database connection failed; check the database service, TLS settings and backup password file': 'database',
        'Backup authority check failed; review the read-only backup role and the single-tenant database identity': 'authority',
        'Backup retention failed; review protected archive state, permissions and the cycle time budget': 'retention',
        'Backup health publication failed; restore the private writable runtime directory before restarting': 'health-publication',
        'Backup cycle timed out; review database/storage performance and the configured time budget': 'deadline',
        'Database backup failed; check PostgreSQL 16 tools, backup role permissions and the configured size/time limits': 'archive',
    }
    observed = {categories[line] for line in output.decode('utf-8', errors='replace').splitlines() if line in categories}
    print('Backup diagnostic: failure categories=' + (','.join(sorted(observed)) or 'unclassified; raw output retained privately'))
    for mount in service['Mounts']:
        if mount['Destination'] == '/var/lib/nethub-backups' and mount['Type'] == 'volume':
            volume = json.loads(docker('volume', 'inspect', project + '_database-backups'))[0]
            if volume['Labels'].get('com.docker.compose.project') != project or volume['Mountpoint'] != mount['Source']:
                raise ValueError('archive volume ownership changed')
            path = Path(mount['Source'])
            if path.resolve(strict=True) != path:
                raise ValueError('archive mountpoint is not canonical')
            info = path.lstat()
            print('Backup diagnostic: archive uid=' + str(info.st_uid) + ' mode=' + oct(stat.S_IMODE(info.st_mode)))
    password = stage / 'deployment/secrets/backup/pg_nethub_backup'
    if password.resolve(strict=True) != password:
        raise ValueError('password path is not canonical')
    info = password.lstat()
    print('Backup diagnostic: password regular=' + str(stat.S_ISREG(info.st_mode)) + ' uid=' + str(info.st_uid) + ' mode=' + oct(stat.S_IMODE(info.st_mode)))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print('Backup diagnostic unavailable; private details suppressed (' + type(error).__name__ + ')')
        raise SystemExit(1)
