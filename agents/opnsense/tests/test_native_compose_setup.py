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
    assert result == {'version': 2, 'phase': 'backup_fixture', 'exit_code': 1,
                      'locations': [], 'failed_tests': [],
                      'hints': ['dependency_timeout']}
    assert secret not in str(result)


@pytest.mark.parametrize('raw,code', [(b'x' * (4 * 1024**2 + 1), 1), ('private', 1), (b'', True)],
                         ids=['oversized', 'text', 'boolean-exit'])
def test_unbounded_or_wrong_typed_input_refused(raw, code):
    with pytest.raises(ValueError):
        SETUP.project(raw, code)


def test_missing_phase_is_explicit_and_exit_is_bounded():
    assert SETUP.project(b'private error details', 999) == {
        'version': 2, 'phase': 'unclassified', 'exit_code': -255, 'hints': [],
        'locations': [], 'failed_tests': []}


def test_only_known_source_locations_and_test_identities_survive():
    raw = (b'  File "/private-secret/gui-issuer-host.py", line 180, in run\n'
           b'  File "/private-secret/unknown.py", line 9, in private_method\n'
           b'--- FAIL: TestPebbleCertificateIssuance/private-secret (1s)\n'
           b'--- FAIL: PrivateSecretTest (1s)\n')
    value = SETUP.project(raw, 1)
    assert value['locations'] == [{'source': 'gui_issuer_host', 'line': 180}]
    assert value['failed_tests'] == ['TestPebbleCertificateIssuance']
    assert 'private-secret' not in str(value) and 'PrivateSecretTest' not in str(value)


def test_nested_private_go_log_round_trip_exports_only_known_locations():
    raw = (b'    pebble_host_linux_test.go:180: private-secret endpoint and response\n'
           b'--- FAIL: TestPebbleProtectedHostIssuer/private-secret (1s)\n'
           b'    private-secret.go:12: private-secret\n')
    projected = SETUP.project(raw, 1)
    closed = SETUP.emit(projected)
    assert 'private-secret' not in closed
    result = SETUP.project(closed.encode(), 1)
    assert result['locations'] == [{'source': 'pebble_host_linux_test', 'line': 180}]
    assert result['failed_tests'] == ['TestPebbleProtectedHostIssuer']


def test_host_proof_markers_remain_closed_through_nested_projection():
    raw = (b'NETHUB_HOST_PROOF_MISSING=renewal_verified\n'
           b'NETHUB_HOST_PROOF_MISSING=private-secret\n'
           b'NETHUB_HOST_TEST_EXIT=nonzero\n')
    value = SETUP.project(raw, 1)
    assert value['hints'] == ['host_renewal_verified', 'host_test_exit']
    assert SETUP.project(SETUP.emit(value).encode(), 1)['hints'] == value['hints']
    assert 'private-secret' not in str(value)


def test_go_panic_paths_export_only_known_basename_and_bounded_line():
    raw = (b'\t/private-secret/source/pebble_host_linux_test.go:342 +0x12\n'
           b'\t/private-secret/source/private-secret.go:12 +0x12\n'
           b'\t/private-secret/source/pebble_host_linux_test.go:99999 +0x12\n')
    value = SETUP.project(raw, 1)
    assert value['locations'] == [{'source': 'pebble_host_linux_test', 'line': 342}]
    assert 'private-secret' not in SETUP.emit(value)


def test_hardlinked_log_refused(tmp_path):
    import os
    path = tmp_path / 'private.log'
    path.write_bytes(b'NETHUB_NATIVE_PHASE=relay\n')
    os.link(path, tmp_path / 'linked.log')
    with pytest.raises(ValueError):
        SETUP.inspect(path, 1)
