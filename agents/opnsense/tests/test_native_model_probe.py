"""Keep private model diagnostics out of uploaded failure metadata."""
import copy
import importlib.util
import json
import os
from pathlib import Path

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/native_model_probe.py'
SPEC = importlib.util.spec_from_file_location('native_model_probe_test', SOURCE)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def failure():
    return {'success': False,
        'message': 'Native credential rotation model operation failed; local recovery may be required',
        'native_phase': 'private_lock',
        'failure_context': {'kind': 'RuntimeException', 'source': 'entry', 'line': 22}}


def test_model_failure_projection_contains_only_known_metadata():
    result = PROBE.project_failure(json.dumps(failure()).encode())
    PROBE.validate_projection(result)
    assert result == {'phase': 'private_lock', 'kind': 'RuntimeException', 'source': 'entry', 'line': 22}


def test_native_storage_receipt_accepts_only_fixed_booleans():
    value = dict.fromkeys(PROBE.STORAGE_FIELDS, False)
    PROBE.validate_storage(value)
    value['lock_mode_private'] = 'private-value-must-not-escape'
    with pytest.raises(ValueError, match='Unexpected private storage condition fields'):
        PROBE.validate_storage(value)
    value['lock_mode_private'] = True
    value['private_path'] = 'private-value-must-not-escape'
    with pytest.raises(ValueError, match='Unexpected private storage condition fields'):
        PROBE.validate_storage(value)


@pytest.mark.parametrize('value', [
    {'available': True, 'stage': 'request', 'kind': 'protocol'},
    {'available': False, 'stage': 'unavailable', 'kind': 'unavailable'},
])
def test_closed_trust_failure_projection_is_accepted(value):
    PROBE.validate_trust_failure(value)


@pytest.mark.parametrize('field,value', [('stage', 'private content'), ('kind', 'private content'),
    ('stage', []), ('kind', {}), ('available', 1), ('message', 'private content')])
def test_trust_failure_projection_refuses_unknown_or_extra_metadata(field, value):
    record = {'available': True, 'stage': 'request', 'kind': 'protocol'}
    record[field] = value
    with pytest.raises(ValueError):
        PROBE.validate_trust_failure(record)


def test_missing_private_trust_diagnostic_does_not_invent_a_cause(tmp_path):
    assert PROBE.trust_failure(tmp_path) == {'available': False, 'stage': 'unavailable', 'kind': 'unavailable'}


@pytest.mark.skipif(not hasattr(os, 'geteuid') or os.geteuid() != 0, reason='Protected evidence requires a POSIX root-owned fixture')
def test_actual_root_owned_diagnostic_is_bounded_and_refuses_links_and_permissions(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path/'rotation-trust-diagnostic.json'
    raw = b'{"kind":"protocol","stage":"request","version":1}\n'
    path.write_bytes(raw); path.chmod(0o600)
    accepted = {'available': True, 'stage': 'request', 'kind': 'protocol'}
    missing = {'available': False, 'stage': 'unavailable', 'kind': 'unavailable'}
    assert PROBE.trust_failure(tmp_path) == accepted
    path.chmod(0o644)
    assert PROBE.trust_failure(tmp_path) == missing
    path.chmod(0o600)
    other = tmp_path/'unrelated'
    os.link(path, other)
    assert PROBE.trust_failure(tmp_path) == missing
    other.unlink()
    assert PROBE.trust_failure(tmp_path) == accepted
    path.rename(other); path.symlink_to(other)
    assert PROBE.trust_failure(tmp_path) == missing and other.read_bytes() == raw
    path.unlink(); other.rename(path)
    path.write_bytes(b' ' * 513)
    assert PROBE.trust_failure(tmp_path) == missing


def test_nested_rotation_receipt_cannot_bypass_trust_metadata_validation():
    value = dict.fromkeys(PROBE.ROTATION_FLAGS, False)
    value.update(phase='absent', trust_sync_failure={'available': True, 'stage': 'request', 'kind': 'protocol'})
    PROBE.validate_rotation_conditions(value)
    value['trust_sync_failure']['credential'] = 'must not escape'
    with pytest.raises(ValueError):
        PROBE.validate_rotation_conditions(value)


@pytest.mark.parametrize('payload', [
    {'version': 1, 'stage': 'request', 'kind': 'private content'},
    {'version': 1, 'stage': 'private content', 'kind': 'protocol'},
    {'version': 1, 'stage': 'request', 'kind': 'protocol', 'secret': 'private content'},
])
def test_untrusted_private_diagnostic_is_not_exported(tmp_path, payload):
    tmp_path.chmod(0o700)
    path = tmp_path/'rotation-trust-diagnostic.json'
    path.write_text(json.dumps(payload, sort_keys=True, separators=(',', ':'))+'\n')
    path.chmod(0o600)
    assert PROBE.trust_failure(tmp_path) == {'available': False, 'stage': 'unavailable', 'kind': 'unavailable'}


@pytest.mark.parametrize('phase', ['absent', 'invalid', 'prepared', 'received'])
def test_rotation_condition_receipt_accepts_only_known_phase_and_booleans(phase):
    value = dict.fromkeys(PROBE.ROTATION_FLAGS, False)
    value['phase'] = phase
    PROBE.validate_rotation_conditions(value)
    value['pending_valid'] = 'private-value-must-not-escape'
    with pytest.raises(ValueError):
        PROBE.validate_rotation_conditions(value)
    value['pending_valid'] = True
    value['candidate'] = 'private-value-must-not-escape'
    with pytest.raises(ValueError):
        PROBE.validate_rotation_conditions(value)


@pytest.mark.parametrize('phase', ['private-value-must-not-escape', [], {}, None, True])
def test_unknown_rotation_phase_is_not_exported(phase):
    value = dict.fromkeys(PROBE.ROTATION_FLAGS, False)
    value['phase'] = phase
    with pytest.raises(ValueError):
        PROBE.validate_rotation_conditions(value)


@pytest.mark.parametrize('mutation', ['extra', 'phase', 'source', 'kind', 'line', 'message', 'success', 'context_extra'])
def test_private_or_malformed_model_failure_is_not_projected(mutation):
    value = copy.deepcopy(failure())
    if mutation == 'extra':
        value['device_secret'] = 'private-value-must-not-escape'
    elif mutation == 'phase':
        value['native_phase'] = 'private-value-must-not-escape'
    elif mutation in ('source', 'kind'):
        value['failure_context'][mutation] = 'private-value-must-not-escape'
    elif mutation == 'line':
        value['failure_context']['line'] = True
    elif mutation == 'message':
        value['message'] = 'private-value-must-not-escape'
    elif mutation == 'success':
        value['success'] = True
    else:
        value['failure_context']['phase'] = 'private-value-must-not-escape'
    result = PROBE.project_failure(json.dumps(value).encode())
    PROBE.validate_projection(result)
    assert result == {'phase': 'unclassified', 'kind': 'other', 'source': 'other', 'line': 0}
    assert 'private-value' not in json.dumps(result)
