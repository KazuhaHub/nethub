"""Record only fixed phases of the remaining owned Compose acceptance."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


PHASES = ('runtime_log_scan', 'privileged_service_checks', 'authority_process_recovery',
          'issuer_database_recovery', 'stack_teardown', 'external_proxy',
          'migration_failure', 'image_export', 'completed')


def validate(value):
    if (not isinstance(value, dict) or set(value) != {'version', 'phase', 'passed'}
            or type(value['version']) is not int or value['version'] != 1
            or not isinstance(value['phase'], str) or value['phase'] not in PHASES
            or type(value['passed']) is not bool or value['passed'] != (value['phase'] == 'completed')):
        raise ValueError('Unexpected owned Compose phase')


def read_phase(directory):
    path = directory / 'compose-tail.json'
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024
            or path.resolve() != path.absolute()):
        raise ValueError('Owned Compose phase storage changed')
    value = json.loads(path.read_bytes())
    validate(value)
    return value


def record_phase(directory, phase):
    value = {'version': 1, 'phase': phase, 'passed': phase == 'completed'}
    validate(value)
    if (sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise ValueError('Fresh hosted Linux root required')
    directory = directory.absolute()
    info = directory.lstat()
    if directory.resolve() != directory or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Private owned Compose evidence required')
    path = directory / 'compose-tail.json'
    if path.exists() or path.is_symlink():
        read_phase(directory)
        info = path.lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('Private owned Compose phase required')
    descriptor, name = tempfile.mkstemp(prefix='.compose-tail-', dir=directory)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, separators=(',', ':'))
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--phase', required=True, choices=PHASES)
    args = parser.parse_args()
    record_phase(args.directory, args.phase)
