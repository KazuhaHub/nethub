"""Run the guarded private flow and publish only closed outcomes."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import traceback

from cold_flow import PHASES, ROOT, admission, exercise
from cold_guard import read_json, save_once
from host_layout import valid_tags
from linux_guest import invoke


PROOFS = ('original_source_reaped_before_distinct_target',
          'original_native_enrollment_key_CSR_assignment_process_checks_alias_preserved',
          'original_registered_account_and_complete_database_restored',
          'same_original_initial_request_issued_and_native_applied_acknowledged',
          'original_normal_Open_grant_retained_without_SQL_creation_or_renewal',
          'same_route_verified_TLS_before_restore_and_after_actual_issuance',
          'normal_native_Remove_server_revocation_and_route_closure',
          'owned_guests_and_independent_CA_cleaned')
TIMINGS = ('baseline_route_recovery_ms', 'initial_issuance_recovery_ms', 'checkpoint_start_to_native_issuance_ms')
FILES = {'cold_flow.py', 'cold_route.py', 'cold_console.py', 'cold_witness.py', 'source_host.py',
         'target_host.py', 'host_checkpoint.py', 'linux_guest.py', 'cold_native.py', 'cold_native_probe.py',
         'bootstrap.py', 'guest.py'}


def success(value, head):
    if (not isinstance(value, dict) or any(value.get(key) is not True for key in PROOFS)
            or value.get('public_operator_durable_custody_renewal_clock_or_full_goal_accepted') is not False
            or any(type(value.get(key)) is not int or not 0 < value[key] <= 7200000 for key in TIMINGS)):
        raise ValueError('Complete isolated recovery proofs required')
    return {'version': 1, 'source_head': head, 'passed': True,
            **{key: value[key] for key in PROOFS + TIMINGS},
            'public_operator_durable_custody_renewal_clock_or_full_goal_accepted': False}


def failure(error, head, phase):
    locations = []
    for frame in traceback.extract_tb(error.__traceback__):
        name = Path(frame.filename).name
        if name in FILES and 1 <= frame.lineno <= 20000:
            locations.append({'source': name, 'line': frame.lineno})
    return {'version': 1, 'source_head': head, 'passed': False,
            'phase': phase if phase in PHASES else 'unavailable',
            'failure_kind': 'timeout' if isinstance(error, TimeoutError) else 'other',
            'locations': locations[-16:], 'full_recovery_or_goal_accepted': False}


def run(control):
    admission(control)
    value = read_json(control / 'inputs.json')
    expected = {'version', 'source_head', 'images', 'images_sha256', 'tags', 'sdk', 'witness_binary', 'witness_binary_sha256'}
    if (not isinstance(value, dict) or set(value) != expected or type(value['version']) is not int or value['version'] != 1
            or value['source_head'] != os.environ.get('NETHUB_SOURCE_HEAD') or not valid_tags(value['tags'])
            or re.fullmatch('[a-f0-9]{40}', value['source_head']) is None):
        raise ValueError('Exact private cold recovery inputs required')
    if invoke(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], 'Cold operation source identity').decode().strip() != value['source_head']:
        raise ValueError('Cold operation checkout differs')
    invoke(['git', '-C', str(ROOT), 'diff', '--exit-code', 'HEAD'], 'Cold operation clean tracked source')
    for field in ('images', 'sdk', 'witness_binary'):
        path = Path(value[field])
        info = path.lstat()
        if (path != path.resolve(strict=True) or path.parent != control / 'inputs'
                or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != (0o555 if field == 'witness_binary' else 0o600)
                or not 0 < info.st_size <= (2 * 1024**3 if field == 'images' else 128 * 1024**2)):
            raise ValueError('Owned staged cold recovery input required')
    for field in ('images', 'witness_binary'):
        with Path(value[field]).open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != value[field + '_sha256']:
            raise ValueError('Original staged cold recovery input differs')
    # Capture only known phase labels. The operation's raw stdout remains private
    # in systemd's log, while this result never contains exception text or inputs.
    import cold_flow
    phase = 'guard_admission'
    original = cold_flow.stage

    def observed(name):
        nonlocal phase
        original(name)
        phase = name

    cold_flow.stage = observed
    try:
        result = exercise(control, Path(value['images']), value['tags'], Path(value['witness_binary']), Path(value['sdk']))
        projection = success(result, value['source_head'])
    except Exception as error:
        projection = failure(error, value['source_head'], phase)
        save_once(control / 'operation-result.json', projection)
        raise SystemExit('Isolated cold recovery failed; closed result retained') from None
    finally:
        cold_flow.stage = original
    save_once(control / 'operation-result.json', projection)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        if len(sys.argv) != 2:
            raise ValueError('Owned cold operation control required')
        run(Path(sys.argv[1]))
    except Exception:
        raise SystemExit('Isolated cold recovery input refused') from None
