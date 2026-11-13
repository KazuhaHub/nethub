"""Read the actual native backend; retain only closed failure metadata."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET


PHASES = ('arguments', 'private_lock', 'private_input', 'native_load', 'native_identity',
          'native_store', 'native_dispatch', 'unconfirmed_python_read', 'php_timeout', 'unclassified')
KINDS = ('Error', 'ErrorException', 'TypeError', 'ValueError', 'RuntimeException', 'other')
SOURCES = ('entry', 'store', 'gui_store', 'app_config', 'config', 'model', 'enrollment', 'other')
STORAGE_FIELDS = ('state_exists', 'state_directory', 'state_owner_root', 'state_mode_private',
                  'state_canonical', 'lock_exists', 'lock_regular', 'lock_owner_root',
                  'lock_mode_private', 'lock_single_link', 'lock_empty', 'lock_canonical')
ROTATION_FLAGS = ('pending_exists', 'pending_valid', 'native_readable',
                  'current_matches_before', 'current_matches_after')
ROUTE_FLAGS = ('service_running', 'model_enabled', 'operator_stopped', 'disabled', 'revoked',
               'runtime_readable', 'runtime_claim_matches_model', 'runtime_token_matches_model')
ROUTE_ACTIONS = ('start', 'restart', 'unchanged', 'stop', 'quarantined', 'unavailable')
ROUTE_EVENTS = ('login_success', 'login_failure', 'proxy_success', 'proxy_failure',
                'control_closed', 'reconnect')
TRUST_STAGES = ('recover', 'native_snapshot', 'binding', 'history', 'request', 'verify', 'apply', 'report', 'unclassified')
TRUST_KINDS = ('protocol', 'transaction', 'native', 'storage', 'value', 'type', 'key', 'unclassified')


def validate_trust_failure(value):
    if (not isinstance(value, dict) or set(value) != {'available', 'stage', 'kind'}
            or type(value['available']) is not bool
            or not isinstance(value['stage'], str) or not isinstance(value['kind'], str)
            or (value['available'] and (value['stage'] not in TRUST_STAGES or value['kind'] not in TRUST_KINDS))
            or (not value['available'] and (value['stage'], value['kind']) != ('unavailable', 'unavailable'))):
        raise ValueError('Unexpected trust failure metadata')


def trust_failure(state=Path('/var/db/nethub-agent')):
    """Project a protected local receipt without exporting its raw bytes."""
    missing = {'available': False, 'stage': 'unavailable', 'kind': 'unavailable'}
    path = state / 'rotation-trust-diagnostic.json'
    try:
        parent, info = state.lstat(), path.lstat()
        if (state.resolve() != state or path.resolve() != path
                or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) != 0o700
                or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= 512):
            return missing
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                return missing
            raw = stream.read(513)
        if len(raw) > 512:
            return missing
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {'version', 'stage', 'kind'}
                or type(value['version']) is not int or value['version'] != 1
                or raw != (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()):
            return missing
        result = {'available': True, 'stage': value['stage'], 'kind': value['kind']}
        validate_trust_failure(result)
        return result
    except (OSError, ValueError, TypeError):
        return missing


def validate_route_conditions(value):
    if (not isinstance(value, dict) or set(value) != set(ROUTE_FLAGS) | {
            'reconcile_success', 'reconcile_action', 'events'}
            or any(type(value[key]) is not bool for key in ROUTE_FLAGS)
            or value['reconcile_success'] is not None and type(value['reconcile_success']) is not bool
            or value['reconcile_action'] not in ROUTE_ACTIONS
            or not isinstance(value['events'], list) or len(value['events']) > 10
            or any(event not in ROUTE_EVENTS for event in value['events'])):
        raise ValueError('Unexpected native route conditions')


def route_conditions(root=Path('/'), runner=subprocess.run):
    """Compare local bindings without exporting model values or arbitrary logs."""
    state = root / 'var/db/nethub-agent'
    value = dict.fromkeys(ROUTE_FLAGS, False)
    value.update(reconcile_success=None, reconcile_action='unavailable', events=[])
    result = runner(['/usr/sbin/service', 'nethub_agent_frpc', 'onestatus'],
                    capture_output=True, timeout=5)
    value['service_running'] = result.returncode == 0
    for name in ('operator_stopped', 'disabled', 'revoked'):
        value[name] = (state / ('stopped' if name == 'operator_stopped' else name)).exists()
    model = ET.parse(root / 'conf/config.xml').find('OPNsense/NetHubAgent')
    if model is None:
        raise ValueError('Native route model unavailable')
    value['model_enabled'] = model.findtext('enabled') == '1'
    try:
        runtime = tomllib.loads((root / 'usr/local/etc/nethub-agent/frpc.toml').read_text())
        value['runtime_readable'] = True
        for key, section, field, model_field in (
                ('runtime_claim_matches_model', 'metadatas', 'domain_claim', 'domain_claim'),
                ('runtime_token_matches_model', 'auth', 'token', 'frp_token')):
            expected = model.findtext(model_field)
            value[key] = bool(expected) and runtime.get(section, {}).get(field) == expected
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    try:
        reconcile = json.loads((state / 'state.json').read_text())
        if type(reconcile.get('success')) is bool:
            value['reconcile_success'] = reconcile['success']
        if reconcile.get('action') in ROUTE_ACTIONS:
            value['reconcile_action'] = reconcile['action']
    except (OSError, ValueError, AttributeError):
        pass
    try:
        with (root / 'var/log/nethub-agent/frpc.log').open('rb') as source:
            source.seek(0, 2)
            source.seek(max(0, source.tell() - 8192))
            lines = source.read().decode('utf-8', errors='replace').splitlines()[-10:]
        for line in lines:
            for marker, event in (
                    ('login to server success', 'login_success'),
                    ('login to the server failed', 'login_failure'),
                    ('start proxy success', 'proxy_success'), ('start error', 'proxy_failure'),
                    ('control writer is closing', 'control_closed'), ('reconnect', 'reconnect')):
                if marker in line.lower():
                    value['events'].append(event)
                    break
    except OSError:
        pass
    validate_route_conditions(value)
    return value


def validate_rotation_conditions(value):
    if (not isinstance(value, dict) or set(value) not in (set(ROTATION_FLAGS) | {'phase'},
            set(ROTATION_FLAGS) | {'phase', 'trust_sync_failure'})
            or any(type(value[key]) is not bool for key in ROTATION_FLAGS)
            or value['phase'] not in ('absent', 'invalid', 'prepared', 'received')):
        raise ValueError('Unexpected rotation recovery conditions')
    if 'trust_sync_failure' in value:
        validate_trust_failure(value['trust_sync_failure'])


def rotation_conditions():
    """Inspect retained recovery state without retrying HTTP or native saves."""
    sys.path.insert(0, '/usr/local/opnsense/scripts/nethub-agent')
    from rotation import RotationJournal
    from rotation_backend import NativeRotationBackend, replacement
    value = dict.fromkeys(ROTATION_FLAGS, False)
    value['phase'] = 'absent'
    value['trust_sync_failure'] = trust_failure()
    pending = None
    journal = RotationJournal('/var/db/nethub-agent')
    value['pending_exists'] = journal.path.exists() or journal.path.is_symlink()
    if value['pending_exists']:
        value['phase'] = 'invalid'
        try:
            pending = journal._read()
            value.update(pending_valid=True, phase=pending['phase'])
        except Exception:
            pass
    try:
        current = NativeRotationBackend().read()
        value['native_readable'] = True
        if pending is not None and pending['native_before'] is not None:
            value['current_matches_before'] = current == pending['native_before']
            if pending['phase'] == 'received':
                value['current_matches_after'] = current == replacement(pending['native_before'], pending['assignment'])
    except Exception:
        pass
    return value


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
    if sys.argv[1:] == ['route']:
        print(json.dumps(route_conditions()))
    elif sys.argv[1:] == ['rotation']:
        print(json.dumps(rotation_conditions()))
    elif sys.argv[1:] == ['storage']:
        print(json.dumps(storage_conditions()))
    elif not sys.argv[1:]:
        print(json.dumps(read_native()))
    else:
        raise SystemExit(2)
