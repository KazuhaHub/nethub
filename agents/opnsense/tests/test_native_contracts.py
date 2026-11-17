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
    groups['service']['native_cases_passed'] = ['test_restart_and_lost_reply_keep_identical_original_events',
        'test_failure_keeps_the_original_lock_captures_real_outbox_and_restores_bytes',
        'test_exact_normal_delivery_replay_browser_and_recovery_keep_native_control',
        'test_unknown_native_failure_is_never_replayed_and_restore_does_not_mask_it[False]',
        'test_unknown_native_failure_is_never_replayed_and_restore_does_not_mask_it[True]',
        'test_interrupted_arm_restores_the_original_template_without_starting_cli',
        'test_recent_failure_context_never_exports_private_child_fields',
        'test_frps_ping_plugin_categories_are_closed_and_never_export_private_text',
        'test_frps_read_failure_keeps_authz_hints_and_is_closed',
        'test_witness_change_retains_fixed_reason_and_never_replays_WAN[process]',
        'test_witness_change_retains_fixed_reason_and_never_replays_WAN[control]',
        'test_witness_change_retains_fixed_reason_and_never_replays_WAN[route]',
        'test_wan_inspection_retains_original_closed_ssh_kind_without_replay[command_timeout]',
        'test_original_ssh_failure_is_not_replaced_by_a_restore_failure',
        'test_identity_failure_writes_closed_console_evidence_and_keeps_the_original_failure',
        'test_console_evidence_is_only_collected_for_the_identity_phase',
        'test_unwritable_console_evidence_never_replaces_the_original_failure',
        'test_late_route_gap_delays_readiness_without_replaying_or_changing_first_recovery_time',
        'test_persistent_late_missing_route_stays_failed_at_the_original_deadline',
        'test_observer_restart_passes_with_window_entirely_after_restart',
        'test_third_observer_loss_is_terminal_and_never_restarted',
        'test_restart_counts_agree_when_the_clock_fails_right_after_a_restart',
        'test_recovery_console_timeout_makes_identity_console_unusable_without_writing',
        'test_settling_validator_binds_the_window_to_the_last_restart',
        'test_revoke_stop_precedes_backlog_delivery_and_clear_requires_ack',
        'test_native_lockf_excludes_both_python_operations',
        'test_native_install_guard_and_reconcile_share_the_original_lock',
        'test_rotation_observes_actual_scheduler_lock_without_losing_busy_response',
        'test_rotation_waits_for_short_contention_without_replaying_native_work',
        'test_external_lock_mode_is_hardened_without_replacing_its_inode',
        'test_rotation_failure_keeps_only_closed_private_trust_metadata',
        'test_private_diagnostic_write_failure_preserves_the_original_closed_error',
        'test_periodic_trust_failure_does_not_overwrite_rotation_diagnostic']
    groups['wire']['native_cases_passed'] = ['test_native_rotation_model_keeps_policy_and_confirms_single_save[journal]',
        'test_actual_root_owned_diagnostic_is_bounded_and_refuses_links_and_permissions']
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


@pytest.mark.parametrize('change', ['missing_native', 'missing_recovery', 'skipped_case', 'failed_guest', 'missing_group', 'boolean_exit', 'missing_audit', 'missing_settling', 'missing_installed_audit'])
def test_a_top_level_green_flag_cannot_hide_missing_or_failed_checks(change):
    result = copy.deepcopy(receipt())
    if change == 'missing_native':
        result['groups']['enrollment']['native_cases_passed'] = []
    elif change == 'missing_recovery':
        result['groups']['wire']['native_cases_passed'] = []
    elif change == 'missing_audit':
        result['groups']['service']['native_cases_passed'].remove('test_restart_and_lost_reply_keep_identical_original_events')
    elif change == 'missing_settling':
        result['groups']['service']['native_cases_passed'].remove('test_persistent_late_missing_route_stays_failed_at_the_original_deadline')
    elif change == 'missing_installed_audit':
        result['groups']['service']['native_cases_passed'].remove('test_exact_normal_delivery_replay_browser_and_recovery_keep_native_control')
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


@pytest.mark.parametrize('name', ['test_restart_and_lost_reply_keep_identical_original_events',
                                'test_revoke_stop_precedes_backlog_delivery_and_clear_requires_ack',
                                'test_native_lockf_excludes_both_python_operations',
                                'test_native_install_guard_and_reconcile_share_the_original_lock',
                                'test_rotation_waits_for_short_contention_without_replaying_native_work'])
def test_skipped_native_lockf_case_is_not_a_pass(tmp_path, name):
    report = tmp_path / 'tests.xml'
    report.write_text(f'<testsuite><testcase name="{name}"><skipped/></testcase><testcase name="test_plain"/></testsuite>')
    result = NATIVE.summarize_xml(report)
    assert result == {'tests': 2, 'passed': 1, 'native_cases_passed': [], 'nonpassing_cases': [name]}


def test_required_parameter_identity_keeps_only_the_allowlisted_variant(tmp_path):
    report = tmp_path / 'tests.xml'
    base = 'test_native_rotation_model_keeps_policy_and_confirms_single_save'
    report.write_text(f'<testsuite><testcase name="{base}[native]"/>'
                      f'<testcase name="{base}[journal]"/>'
                      '<testcase name="test_plain[private-value-must-not-escape]"/></testsuite>')
    result = NATIVE.summarize_xml(report)
    assert result == {'tests': 3, 'passed': 3, 'nonpassing_cases': [],
                      'native_cases_passed': [base + '[journal]']}


@pytest.mark.parametrize('outcome', ['skipped', 'failure', 'error'])
def test_nonpassing_required_parameter_variant_never_receives_credit(tmp_path, outcome):
    report = tmp_path / 'tests.xml'
    name = 'test_native_rotation_model_keeps_policy_and_confirms_single_save[journal]'
    report.write_text(f'<testsuite><testcase name="{name}"><{outcome}/></testcase></testsuite>')
    result = NATIVE.summarize_xml(report)
    assert result == {'tests': 1, 'passed': 0, 'native_cases_passed': [], 'nonpassing_cases': [name]}
