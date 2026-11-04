"""Project fixed early fixture phases and dependency errors without child output."""
from pathlib import Path
import stat
import re
import sys


PHASES = ('preflight', 'build_inputs', 'http01', 'gui_issuer', 'gui_acme_build',
          'pebble_primitives', 'gui_host_source_checks', 'gui_host_runtime', 'gui_host_build', 'setup_build',
          'frps_smoke', 'initialization', 'stack_start', 'backup_fixture',
          'provider_key', 'administrator', 'relay', 'native_guest')
ERRORS = {'dependency_timeout': (b'TLS handshake timeout', b'i/o timeout', b'context deadline exceeded'),
          'dependency_rate_limit': (b'429 Too Many Requests', b'toomanyrequests:'),
          'storage_full': (b'no space left on device',),
          'name_resolution': (b'Temporary failure in name resolution', b'no such host'),
          'database_fingerprint': (b'stable complete recovery database fingerprint',
                                   b'recovery fingerprint detects changed schema grant',
                                   b'recovery fingerprint returns to original after grant removal')}
SOURCES = {'gui-issuer-host.py': 'gui_issuer_host', 'test_gui_issuer_host.py': 'gui_host_source_checks'}
SOURCES.update({name: name.removesuffix('.go') for name in (
    'pebble_integration_test.go', 'pebble_http01_test.go', 'pebble_host_linux_test.go',
    'pebble_host_enrollment_linux_test.go', 'pebble_database_test.go', 'pebble_coordinator_test.go')})
TESTS = ('TestPebbleOrderAdmission', 'TestPebbleHTTP01Validation', 'TestPebbleCertificateIssuance',
         'TestPebbleCoordinatorRecovery', 'TestPebbleProtectedHostIssuer',
         'TestPebbleProtectedHostIssuerRenewal', 'TestPebbleProtectedHostAccountProvisioning')


def project(raw, code):
    if not isinstance(raw, bytes) or len(raw) > 4 * 1024**2 or type(code) is not int:
        raise ValueError('Bounded fixture log and numeric exit required')
    phases = [line.removeprefix(b'NETHUB_NATIVE_PHASE=').decode('ascii')
              for line in raw.splitlines() if line.startswith(b'NETHUB_NATIVE_PHASE=')
              and line.removeprefix(b'NETHUB_NATIVE_PHASE=') in {value.encode() for value in PHASES}]
    locations = set()
    failed = set()
    for line in raw.splitlines():
        for name, source in SOURCES.items():
            match = re.fullmatch(rb'\s*File "[^"\r\n]*/' + re.escape(name.encode())
                                 + rb'", line ([0-9]{1,5}), in [a-zA-Z0-9_<>]+', line)
            if match and 1 <= int(match[1]) <= 10000:
                locations.add((source, int(match[1])))
            go = re.match(rb'\s*' + re.escape(name.encode()) + rb':([0-9]{1,5}):', line)
            emitted = re.fullmatch(b'NETHUB_NATIVE_LOCATION=' + source.encode() + rb':([0-9]{1,5})', line)
            for match in (go, emitted):
                if match and 1 <= int(match[1]) <= 10000:
                    locations.add((source, int(match[1])))
        for name in TESTS:
            if re.match(rb'\s*--- FAIL: ' + name.encode() + rb'(?:[/\s]|$)', line):
                failed.add(name)
    if len(locations) > 64:
        raise ValueError('Too many fixture source locations')
    return {'version': 2, 'phase': phases[-1] if phases else 'unclassified',
            'exit_code': code if -255 <= code <= 255 else -255,
            'locations': [{'source': source, 'line': line} for source, line in sorted(locations)],
            'failed_tests': sorted(failed),
            'hints': sorted(name for name, needles in ERRORS.items() if any(value in raw for value in needles)
                            or b'NETHUB_NATIVE_HINT=' + name.encode() in raw.splitlines())}


def inspect(path: Path, code):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or path != path.resolve() or info.st_size > 4 * 1024**2):
        raise ValueError('Private fixture log unavailable')
    return project(path.read_bytes(), code)


def emit(value):
    # Emit only the closed projection, never a line from the private Go log.
    lines = ['--- FAIL: ' + name for name in value['failed_tests']]
    lines += ['NETHUB_NATIVE_LOCATION=' + item['source'] + ':' + str(item['line']) for item in value['locations']]
    lines += ['NETHUB_NATIVE_HINT=' + name for name in value['hints']]
    return '\n'.join(lines)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('One private fixture log required')
    try:
        print(emit(inspect(Path(sys.argv[1]), 1)))
    except (OSError, ValueError):
        print('NETHUB_NATIVE_NESTED_LOG=unavailable')
