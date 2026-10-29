"""Keep private model diagnostics out of uploaded failure metadata."""
import copy
import importlib.util
import json
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
