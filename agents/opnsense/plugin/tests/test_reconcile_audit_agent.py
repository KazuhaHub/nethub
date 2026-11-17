"""Exercise real agent failure retention and authenticated acknowledgement boundaries."""
import json
from unittest import mock

import pytest
from test_lifecycle_agent import case
from protocol import ProtocolError
from reconcile_audit import Outbox


def box(case):
    return Outbox(case.agent.state, '11111111-1111-4111-8111-111111111111')


def fail(case):
    case.reject = True
    result = case.agent.apply('reconcile')
    assert result['success'] is False and result['audit_recorded'] is True
    assert len(box(case).batch()) == 1
    return box(case).batch()


def test_successful_later_reconcile_cannot_erase_failed_event(case):
    original = fail(case)
    case.reject = False
    assert case.agent.apply('reconcile')['success']
    assert box(case).batch() == original
    assert 'credential' not in json.dumps(original) and 'message' not in json.dumps(original)


def test_lost_audit_reply_retains_original_and_does_not_repeat_reconcile(case):
    original = fail(case)
    before = case.mutations()
    with mock.patch('lifecycle.report_health', return_value={'revoked': False, 'agent_protocol_version': '1.7.0'}), mock.patch('reconcile_audit.report_events', side_effect=ProtocolError('private raw diagnostic')):
        result = case.agent.apply('report')
    assert result['success'] is False and 'private' not in json.dumps(result)
    assert box(case).batch() == original and case.mutations() == before
    with mock.patch('lifecycle.report_health', return_value={'revoked': False, 'agent_protocol_version': '1.7.0'}), mock.patch('reconcile_audit.report_events', return_value=False) as network:
        assert case.agent.apply('report')['success']
    assert network.call_args.args[3] == original and box(case).batch() == []


def test_old_console_retains_pending_events_without_unsupported_request(case):
    original = fail(case)
    with mock.patch('lifecycle.report_health', return_value={'revoked': False, 'agent_protocol_version': '1.6.0'}), mock.patch('reconcile_audit.report_events') as network:
        result = case.agent.apply('report')
    assert result['success'] is True and result['audit_pending'] is True and 'audit pending' in result['message']
    assert case.agent.status()['last_report']['audit_pending'] is True
    network.assert_not_called()
    assert box(case).batch() == original


def test_revoke_stop_precedes_backlog_delivery_and_clear_requires_ack(case):
    original = fail(case)
    xml = (case.root / 'conf/config.xml').read_bytes()
    def audit_failure(*args):
        assert not case.active and (case.agent.state / 'revoked').exists()
        raise ProtocolError('private unconfirmed reply')
    with mock.patch('lifecycle.request_removal', return_value={'revoked': True, 'agent_protocol_version': '1.7.0'}), mock.patch('reconcile_audit.report_events', side_effect=audit_failure):
        assert not case.agent.apply('unenroll')['success']
    assert box(case).batch() == original and (case.root / 'conf/config.xml').read_bytes() == xml
    assert not (case.agent.state / 'unenroll-confirmed.json').exists()
    with mock.patch('lifecycle.request_removal', return_value={'revoked': True, 'agent_protocol_version': '1.7.0'}), mock.patch('reconcile_audit.report_events', return_value=True):
        assert case.agent.apply('unenroll')['success']
    assert not (case.agent.state / 'reconcile-audit.json').exists()
    assert (case.root / 'conf/config.xml').read_bytes() == xml and not case.active


def test_outbox_storage_failure_cannot_hide_original_failure_or_release_stop(case):
    case.agent.state.mkdir(parents=True, mode=0o700)
    (case.agent.state / 'reconcile-audit.json').write_text('corrupt private data')
    case.reject = True
    result = case.agent.apply('reconcile')
    assert result['success'] is False and result['audit_recorded'] is False
    assert 'private data' not in json.dumps(result)
    assert (case.agent.state / 'reconcile-audit.json').read_text() == 'corrupt private data'
    assert case.agent.apply('disable')['success'] and not case.active


def test_forget_cannot_erase_runtime_keys_while_retained_history_exists(case):
    fail(case)
    original = box(case).batch()
    case.set_enabled(False)  # Model cleared separately, not a confirmed Remove.
    case.agent.backup.write_text('private retained runtime fixture')
    result = case.agent.apply('forget')
    assert result['success'] is False and 'audit' in result['message']
    assert box(case).batch() == original
    assert case.agent.backup.read_text() == 'private retained runtime fixture'
    assert not case.active
