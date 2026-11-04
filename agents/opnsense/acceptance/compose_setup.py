"""Project fixed early fixture phases and dependency errors without child output."""
from pathlib import Path
import stat
import re


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
        for name in TESTS:
            if re.match(rb'\s*--- FAIL: ' + name.encode() + rb'(?:[/\s]|$)', line):
                failed.add(name)
    return {'version': 2, 'phase': phases[-1] if phases else 'unclassified',
            'exit_code': code if -255 <= code <= 255 else -255,
            'locations': [{'source': source, 'line': line} for source, line in sorted(locations)],
            'failed_tests': sorted(failed),
            'hints': sorted(name for name, needles in ERRORS.items() if any(value in raw for value in needles))}


def inspect(path: Path, code):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or path != path.resolve() or info.st_size > 4 * 1024**2):
        raise ValueError('Private fixture log unavailable')
    return project(path.read_bytes(), code)
