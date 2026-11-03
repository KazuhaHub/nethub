"""Project fixed early fixture phases and dependency errors without child output."""
from pathlib import Path
import stat


PHASES = ('preflight', 'build_inputs', 'http01', 'gui_issuer', 'setup_build',
          'frps_smoke', 'initialization', 'stack_start', 'backup_fixture',
          'provider_key', 'administrator', 'relay', 'native_guest')
ERRORS = {'dependency_timeout': (b'TLS handshake timeout', b'i/o timeout', b'context deadline exceeded'),
          'dependency_rate_limit': (b'429 Too Many Requests', b'toomanyrequests:'),
          'storage_full': (b'no space left on device',),
          'name_resolution': (b'Temporary failure in name resolution', b'no such host'),
          'database_fingerprint': (b'stable complete recovery database fingerprint',
                                   b'recovery fingerprint detects changed schema grant',
                                   b'recovery fingerprint returns to original after grant removal')}


def project(raw, code):
    if not isinstance(raw, bytes) or len(raw) > 4 * 1024**2 or type(code) is not int:
        raise ValueError('Bounded fixture log and numeric exit required')
    phases = [line.removeprefix(b'NETHUB_NATIVE_PHASE=').decode('ascii')
              for line in raw.splitlines() if line.startswith(b'NETHUB_NATIVE_PHASE=')
              and line.removeprefix(b'NETHUB_NATIVE_PHASE=') in {value.encode() for value in PHASES}]
    return {'version': 1, 'phase': phases[-1] if phases else 'unclassified',
            'exit_code': code if -255 <= code <= 255 else -255,
            'hints': sorted(name for name, needles in ERRORS.items() if any(value in raw for value in needles))}


def inspect(path: Path, code):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or path != path.resolve() or info.st_size > 4 * 1024**2):
        raise ValueError('Private fixture log unavailable')
    return project(path.read_bytes(), code)
