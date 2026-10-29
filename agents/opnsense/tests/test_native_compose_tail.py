"""Keep post-native failures observable without publishing child output."""
import importlib.util
import json
from pathlib import Path

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/compose_tail.py'
SPEC = importlib.util.spec_from_file_location('native_compose_tail', SOURCE)
TAIL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TAIL)


@pytest.mark.parametrize('phase', TAIL.PHASES)
def test_only_complete_phase_reports_success(phase):
    TAIL.validate({'version': 1, 'phase': phase, 'passed': phase == 'completed'})


@pytest.mark.parametrize('change', ['extra', 'version', 'phase', 'phase_type', 'passed_type', 'false_complete'])
def test_unknown_or_private_phase_metadata_is_refused(change):
    value = {'version': 1, 'phase': 'completed', 'passed': True}
    if change == 'extra': value['private_output'] = 'private-value-must-not-escape'
    elif change == 'version': value['version'] = True
    elif change == 'phase': value['phase'] = 'private-value-must-not-escape'
    elif change == 'phase_type': value['phase'] = []
    elif change == 'passed_type': value['passed'] = 1
    else: value['passed'] = False
    with pytest.raises(ValueError): TAIL.validate(value)


def test_nonhosted_phase_record_never_creates_storage(tmp_path, monkeypatch):
    monkeypatch.setenv('GITHUB_ACTIONS', 'false')
    target = tmp_path / 'must-not-exist'
    with pytest.raises(ValueError, match='Fresh hosted Linux root required'):
        TAIL.record_phase(target, 'runtime_log_scan')
    assert not target.exists()


def test_phase_file_refuses_linked_output(tmp_path):
    target = tmp_path / 'unrelated'
    target.write_text(json.dumps({'version': 1, 'phase': 'completed', 'passed': True}))
    import os
    os.link(target, tmp_path / 'compose-tail.json')
    with pytest.raises(ValueError, match='storage changed'):
        TAIL.read_phase(tmp_path)
