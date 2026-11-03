"""Early failure diagnostics must not copy private child output."""
import importlib.util
from pathlib import Path

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/compose_setup.py'
SPEC = importlib.util.spec_from_file_location('native_compose_setup', SOURCE)
SETUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SETUP)


def test_only_closed_phase_and_hints_survive_private_output():
    secret = 'private-value-must-not-escape'
    result = SETUP.project(('NETHUB_NATIVE_PHASE=http01\n' + secret + '\n'
        'NETHUB_NATIVE_PHASE=backup_fixture\nTLS handshake timeout\n'
        'NETHUB_NATIVE_PHASE=' + secret + '\n').encode(), 1)
    assert result == {'version': 1, 'phase': 'backup_fixture', 'exit_code': 1,
                      'hints': ['dependency_timeout']}
    assert secret not in str(result)


@pytest.mark.parametrize('raw,code', [(b'x' * (4 * 1024**2 + 1), 1), ('private', 1), (b'', True)],
                         ids=['oversized', 'text', 'boolean-exit'])
def test_unbounded_or_wrong_typed_input_refused(raw, code):
    with pytest.raises(ValueError):
        SETUP.project(raw, code)


def test_missing_phase_is_explicit_and_exit_is_bounded():
    assert SETUP.project(b'private error details', 999) == {
        'version': 1, 'phase': 'unclassified', 'exit_code': -255, 'hints': []}


def test_hardlinked_log_refused(tmp_path):
    import os
    path = tmp_path / 'private.log'
    path.write_bytes(b'NETHUB_NATIVE_PHASE=relay\n')
    os.link(path, tmp_path / 'linked.log')
    with pytest.raises(ValueError):
        SETUP.inspect(path, 1)
