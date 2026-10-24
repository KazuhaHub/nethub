"""Exercise local stop intent independently from native model/trust recovery."""
import fcntl
import subprocess
from unittest import mock

import pytest
import test_reconcile as base


@pytest.fixture
def case():
    fixture = base.ReconcileTests()
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.doCleanups()


def test_circuit_stops_without_xml_or_trust_recovery_and_is_persistent(case):
    xml = case.root / 'conf/config.xml'
    xml.write_bytes(b'broken native XML')
    original = xml.read_bytes()
    live = case.agent.live.read_bytes()
    with mock.patch.object(case.agent, 'recover_trust', side_effect=RuntimeError('must not recover')):
        result = case.agent.apply('disable')
    assert result['success'] and not case.active
    marker = case.agent.state / 'disabled'
    assert marker.stat().st_mode & 0o777 == 0o600
    assert xml.read_bytes() == original and case.agent.live.read_bytes() == live
    assert 'NO' in (case.root / 'etc/rc.conf.d/nethub_agent_frpc').read_text()
    # A new agent object represents a later process, not a simulated native boot.
    later = base.MODULE.Agent(case.root, case.command)
    assert later.status()['disabled'] is True
    assert later.apply('disable')['success'] and case.mutations() == ['onestop']


@pytest.mark.parametrize('marker', ['stopped', 'revoked', 'uninstalling'])
def test_release_never_clears_other_stop_conditions(case, marker):
    original = (case.root / 'conf/config.xml').read_bytes()
    assert case.agent.apply('disable')['success']
    (case.agent.state / marker).touch()
    result = case.agent.apply('enable')
    assert result['success'] and not case.active
    assert (case.agent.state / marker).exists()
    assert not (case.agent.state / 'disabled').exists()
    assert (case.root / 'conf/config.xml').read_bytes() == original


def test_release_reconciles_saved_intent_without_writing_native_xml(case):
    original = (case.root / 'conf/config.xml').read_bytes()
    assert case.agent.apply('disable')['success']
    assert case.agent.apply('enable')['success'] and case.active
    assert case.mutations() == ['onestop', 'onestart']
    assert (case.root / 'conf/config.xml').read_bytes() == original
    case.set_enabled(False)
    assert case.agent.apply('disable')['success']
    assert case.agent.apply('enable')['success'] and not case.active


def test_failed_stop_retains_marker_and_does_not_report_success(case):
    original = case.agent.run
    def fail(args, **kwargs):
        if str(args[0]) == '/usr/sbin/service' and args[-1] == 'onestop':
            return subprocess.CompletedProcess(args, 1, '', 'private child diagnostics')
        return original(args, **kwargs)
    case.agent.run = fail
    result = case.agent.apply('disable')
    assert not result['success'] and case.active
    assert (case.agent.state / 'disabled').is_file()
    assert 'NO' in (case.root / 'etc/rc.conf.d/nethub_agent_frpc').read_text()
    assert 'private child' not in str(result)


def test_successful_stop_command_must_also_leave_service_stopped(case):
    original = case.agent.run
    def lie(args, **kwargs):
        if str(args[0]) == '/usr/sbin/service' and args[-1] == 'onestop':
            return subprocess.CompletedProcess(args, 0, '', '')
        return original(args, **kwargs)
    case.agent.run = lie
    assert case.agent.apply('disable')['success'] is False
    assert case.active and (case.agent.state / 'disabled').exists()


def test_rc_write_failure_does_not_prevent_the_stop(case):
    with mock.patch.object(case.agent, 'rc_enable', side_effect=OSError('private filesystem detail')):
        result = case.agent.apply('disable')
    assert not result['success'] and not case.active
    assert (case.agent.state / 'disabled').is_file()
    assert 'private filesystem' not in str(result)


def test_busy_lock_does_not_change_stop_intent(case):
    case.agent.state.mkdir(parents=True)
    with (case.agent.state / 'reconcile.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = case.agent.apply('disable')
    assert result['action'] == 'busy' and not result['success']
    assert not (case.agent.state / 'disabled').exists() and case.active


def test_release_refuses_a_link_without_deleting_its_target(case):
    assert case.agent.apply('disable')['success']
    marker = case.agent.state / 'disabled'
    marker.unlink()
    target = case.root / 'operator-file'
    target.write_text('retain')
    marker.symlink_to(target)
    assert case.agent.apply('enable')['success'] is False
    assert marker.is_symlink() and target.read_text() == 'retain' and not case.active


