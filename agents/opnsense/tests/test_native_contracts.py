"""Reject relabeled sources, skipped native checks and incomplete guest receipts."""
import copy
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('native_contracts', Path(__file__).parents[1] / 'native_contracts.py')
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
HEAD, SHA = 'a' * 40, 'b' * 64


def receipt():
    groups = {name: {'tests': spec[0], 'passed': spec[0], 'exit_code': 0, 'native_cases_passed': [], 'nonpassing_cases': []}
              for name, spec in NATIVE.GROUPS.items()}
    groups['enrollment']['native_cases_passed'] = ['test_enrollment_lock_interoperates_with_native_scheduler_lockf']
    groups['service']['native_cases_passed'] = ['test_native_lockf_excludes_both_python_operations',
        'test_external_lock_mode_is_hardened_without_replacing_its_inode']
    return {'version': 1, 'source_head': HEAD, 'manifest_sha': SHA, 'system': 'FreeBSD',
            'release': '15.1-RELEASE-p4', 'machine': 'amd64', 'uid': 0,
            'groups': groups, 'passed': True, 'source_unchanged': True,
            'installed_opnsense_acceptance': False, 'frpc_installed_and_retested': False,
            'tools': {'pytest': '8.3.5', 'Jinja2': '3.1.6', 'jsonschema': '4.25.1', 'python': '3.13.9'}}


def test_complete_receipt_retains_the_installed_appliance_limit():
    NATIVE.validate_receipt(receipt(), HEAD, SHA)


@pytest.mark.parametrize('field,value', [
    ('source_head', 'c' * 40), ('manifest_sha', 'd' * 64), ('system', 'Linux'),
    ('release', '14.3-RELEASE'), ('uid', False), ('passed', False),
    ('source_unchanged', False), ('installed_opnsense_acceptance', True),
    ('frpc_installed_and_retested', True),
])
def test_relabeling_platform_and_broader_acceptance_claims_fail(field, value):
    result = receipt()
    result[field] = value
    with pytest.raises(ValueError):
        NATIVE.validate_receipt(result, HEAD, SHA)


@pytest.mark.parametrize('change', ['missing_native', 'skipped_case', 'failed_guest', 'missing_group', 'boolean_exit'])
def test_a_top_level_green_flag_cannot_hide_missing_or_failed_checks(change):
    result = copy.deepcopy(receipt())
    if change == 'missing_native':
        result['groups']['enrollment']['native_cases_passed'] = []
    elif change == 'skipped_case':
        result['groups']['service']['passed'] -= 1
    elif change == 'failed_guest':
        result['groups']['wire']['exit_code'] = 1
    elif change == 'missing_group':
        del result['groups']['wire']
    else:
        result['groups']['wire']['exit_code'] = False
    with pytest.raises(ValueError):
        NATIVE.validate_receipt(result, HEAD, SHA)


def test_source_bytes_and_manifest_identity_must_remain_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(NATIVE, 'ROOT', tmp_path)
    (tmp_path / 'source.py').write_bytes(b'public source\n')
    files = {'source.py': NATIVE.digest(b'public source\n')}
    raw = NATIVE.encoded({'version': 1, 'source_head': HEAD, 'files': files})
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    (evidence / 'source.json').write_bytes(raw)
    sha = NATIVE.digest(raw)
    NATIVE.read_manifest(evidence, HEAD, sha)
    with pytest.raises(ValueError):
        NATIVE.read_manifest(evidence, 'c' * 40, sha)
    with pytest.raises(ValueError):
        NATIVE.read_manifest(evidence, HEAD, 'd' * 64)
    (tmp_path / 'source.py').write_bytes(b'changed source\n')
    with pytest.raises(ValueError):
        NATIVE.read_manifest(evidence, HEAD, sha)
    assert not NATIVE.source_matches(tmp_path, {'../outside': SHA})


def test_skipped_native_lockf_case_is_not_a_pass(tmp_path):
    report = tmp_path / 'tests.xml'
    name = 'test_native_lockf_excludes_both_python_operations'
    report.write_text(f'<testsuite><testcase name="{name}"><skipped/></testcase><testcase name="test_plain"/></testsuite>')
    result = NATIVE.summarize_xml(report)
    assert result == {'tests': 2, 'passed': 1, 'native_cases_passed': [], 'nonpassing_cases': [name]}
