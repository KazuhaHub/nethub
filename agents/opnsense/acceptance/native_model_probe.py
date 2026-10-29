"""Read the actual native backend; retain only closed failure metadata."""
import json
from pathlib import Path
import stat
import subprocess
import sys


PHASES = ('arguments', 'private_lock', 'private_input', 'native_load', 'native_identity',
          'native_store', 'native_dispatch', 'unconfirmed_python_read', 'php_timeout', 'unclassified')
KINDS = ('Error', 'ErrorException', 'TypeError', 'ValueError', 'RuntimeException', 'other')
SOURCES = ('entry', 'store', 'gui_store', 'app_config', 'config', 'model', 'enrollment', 'other')
STORAGE_FIELDS = ('state_exists', 'state_directory', 'state_owner_root', 'state_mode_private',
                  'state_canonical', 'lock_exists', 'lock_regular', 'lock_owner_root',
                  'lock_mode_private', 'lock_single_link', 'lock_empty', 'lock_canonical')


def validate_storage(value):
    if (not isinstance(value, dict) or set(value) != set(STORAGE_FIELDS)
            or any(type(item) is not bool for item in value.values())):
        raise ValueError('Unexpected private storage condition fields')


def storage_conditions():
    value = dict.fromkeys(STORAGE_FIELDS, False)
    directory = Path('/var/db/nethub-agent')
    path = directory / 'reconcile.lock'
    try:
        info = directory.lstat()
        value.update(state_exists=True, state_directory=stat.S_ISDIR(info.st_mode),
                     state_owner_root=info.st_uid == 0, state_mode_private=stat.S_IMODE(info.st_mode) == 0o700,
                     state_canonical=directory.resolve() == directory)
    except OSError:
        pass
    try:
        info = path.lstat()
        value.update(lock_exists=True, lock_regular=stat.S_ISREG(info.st_mode),
                     lock_owner_root=info.st_uid == 0, lock_mode_private=stat.S_IMODE(info.st_mode) == 0o600,
                     lock_single_link=info.st_nlink == 1, lock_empty=info.st_size == 0,
                     lock_canonical=path.resolve() == path)
    except OSError:
        pass
    return value


def validate_projection(value):
    if (not isinstance(value, dict) or set(value) != {'phase', 'kind', 'source', 'line'}
            or not isinstance(value['phase'], str) or value['phase'] not in PHASES
            or not isinstance(value['kind'], str) or value['kind'] not in KINDS
            or not isinstance(value['source'], str) or value['source'] not in SOURCES
            or type(value['line']) is not int or not 0 <= value['line'] <= 20000):
        raise ValueError('Unexpected native model failure metadata')


def project_failure(raw):
    fallback = {'phase': 'unclassified', 'kind': 'other', 'source': 'other', 'line': 0}
    try:
        if not isinstance(raw, bytes) or len(raw) > 4096:
            return fallback
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {'success', 'message', 'native_phase', 'failure_context'}
                or value['success'] is not False
                or value['message'] != 'Native credential rotation model operation failed; local recovery may be required'
                or not isinstance(value['failure_context'], dict)
                or set(value['failure_context']) != {'kind', 'source', 'line'}):
            return fallback
        result = dict(value['failure_context'], phase=value['native_phase'])
        validate_projection(result)
        return result
    except (ValueError, TypeError, KeyError):
        return fallback


def read_native():
    sys.path.insert(0, '/usr/local/opnsense/scripts/nethub-agent')
    from rotation import RotationError
    from rotation_backend import NativeRotationBackend
    backend = NativeRotationBackend()
    try:
        return backend.read()
    except RotationError:
        failure = {'phase': 'unconfirmed_python_read', 'kind': 'other', 'source': 'other', 'line': 0}
        try:
            result = subprocess.run(['/usr/local/bin/php', str(backend.script)],
                input=b'{"action":"read","request":[]}', capture_output=True, timeout=5)
            if result.returncode:
                failure = project_failure(result.stdout)
        except subprocess.TimeoutExpired:
            failure['phase'] = 'php_timeout'
        except OSError:
            failure['phase'] = 'unclassified'
        return {'native_model_failure': failure}


if __name__ == '__main__':
    if sys.argv[1:] == ['storage']:
        print(json.dumps(storage_conditions()))
    elif not sys.argv[1:]:
        print(json.dumps(read_native()))
    else:
        raise SystemExit(2)
