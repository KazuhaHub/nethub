"""Reject untested or differently sourced images before native acceptance."""
import copy
import fnmatch
import importlib.util
import json
from pathlib import Path
import sys

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/with_images.py'
sys.path.insert(0, str(SOURCE.parent))
try:
    SPEC = importlib.util.spec_from_file_location('native_image_provenance', SOURCE)
    SUITE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(SUITE)
finally:
    sys.path.pop(0)


def evidence():
    run = {'head_sha': 'a' * 40, 'repository': {'full_name': 'KazuhaHub/nethub'},
           'path': '.github/workflows/ci.yml', 'status': 'completed', 'conclusion': 'success'}
    jobs = [dict(name=name, status='completed', conclusion='success') for name in sorted(SUITE.JOBS)]
    return run, jobs


def test_complete_exact_source_ci_is_required():
    run, jobs = evidence()
    SUITE.validate_run(run, jobs, 'a' * 40)
    for key, replacement in [('head_sha', 'b' * 40), ('path', '.github/workflows/unrelated.yml'),
                             ('status', 'in_progress'), ('conclusion', 'cancelled'),
                             ('repository', {'full_name': 'other/nethub'})]:
        changed = copy.deepcopy(run)
        changed[key] = replacement
        with pytest.raises(SUITE.GuestError):
            SUITE.validate_run(changed, jobs, 'a' * 40)
    with pytest.raises(SUITE.GuestError):
        SUITE.validate_run(run, jobs, 'A' * 40)


def test_native_upload_covers_every_public_outcome_and_image():
    workflow = (SOURCE.parents[3] / '.github/workflows/native-enrolled.yml').read_text(encoding='utf-8')
    prefix = '${{ runner.temp }}/native-enrolled-evidence/'
    patterns = [line.strip()[len(prefix):] for line in workflow.splitlines() if line.strip().startswith(prefix)]
    assert len(patterns) == len(set(patterns))
    assert set(patterns) <= set(SUITE.PUBLIC_FILES) | {'native/*-page.json'}
    missing = [name for name in SUITE.PUBLIC_FILES if not any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)]
    assert missing == [], 'Public native evidence is missing from the artifact upload contract'


def test_native_package_private_fields_are_rejected_before_publication(tmp_path, monkeypatch):
    directory = tmp_path / 'native'
    directory.mkdir()
    (directory / 'installed-package-migration.json').write_text(json.dumps(
        {'passed': True, 'device_secret': 'must-not-be-published'}))
    changed = []
    monkeypatch.setenv('SUDO_UID', '1000')
    monkeypatch.setenv('SUDO_GID', '1000')
    monkeypatch.setattr(SUITE.os, 'chown', lambda *args: changed.append(args), raising=False)
    with pytest.raises(ValueError):
        SUITE.publish_evidence(tmp_path)
    assert changed == []


def test_post_wan_private_fields_are_rejected_before_publication(tmp_path, monkeypatch):
    directory = tmp_path / 'native'
    directory.mkdir()
    (directory / 'post-wan-console-failure.json').write_text(json.dumps(
        {'diagnostic_only': True, 'private': 'must-not-be-published'}))
    changed = []
    monkeypatch.setenv('SUDO_UID', '1000')
    monkeypatch.setenv('SUDO_GID', '1000')
    monkeypatch.setattr(SUITE.os, 'chown', lambda *args: changed.append(args), raising=False)
    with pytest.raises(ValueError, match='Unexpected post-WAN diagnostic'):
        SUITE.publish_evidence(tmp_path)
    assert changed == []


@pytest.mark.parametrize('name', ['installed-reconcile-audit.json', 'installed-reconcile-audit-browser.json'])
def test_installed_audit_private_fields_are_rejected_before_publication(tmp_path, monkeypatch, name):
    directory = tmp_path / 'native'
    directory.mkdir()
    (directory / name).write_text(json.dumps({'passed': True, 'private': 'must-not-be-published'}))
    changed = []
    monkeypatch.setenv('SUDO_UID', '1000')
    monkeypatch.setenv('SUDO_GID', '1000')
    monkeypatch.setattr(SUITE.os, 'chown', lambda *args: changed.append(args), raising=False)
    with pytest.raises(ValueError):
        SUITE.publish_evidence(tmp_path)
    assert changed == []


@pytest.mark.parametrize('name', ['guest-console-probe.json', 'guest-console-after-wan-probe.json'])
def test_console_probe_with_private_extra_field_cannot_be_published(tmp_path, monkeypatch, name):
    directory = tmp_path / 'native'
    directory.mkdir()
    (directory / name).write_text(json.dumps({'passed': True, 'phase': 'complete', 'failure': '',
        'http_status': 200, 'verify_code': 0, 'default_CA_file_available': False,
        'default_CA_directory_available': True, 'private': 'must-not-be-published'}))
    changed = []
    monkeypatch.setenv('SUDO_UID', '1000')
    monkeypatch.setenv('SUDO_GID', '1000')
    monkeypatch.setattr(SUITE.os, 'chown', lambda *args: changed.append(args), raising=False)
    with pytest.raises(ValueError, match='Unexpected closed console probe result'):
        SUITE.publish_evidence(tmp_path)
    assert changed == []


@pytest.mark.parametrize('mutation', ['missing', 'extra', 'duplicate', 'skipped', 'failed', 'live'])
def test_partial_or_substituted_job_evidence_is_refused(mutation):
    run, jobs = evidence()
    if mutation == 'missing':
        jobs.pop()
    elif mutation == 'extra':
        jobs.append(dict(name='unrelated', status='completed', conclusion='success'))
    elif mutation == 'duplicate':
        jobs[-1] = dict(jobs[0])
    elif mutation in ('skipped', 'failed'):
        jobs[-1]['conclusion'] = mutation
    else:
        jobs[-1]['status'] = 'in_progress'
    with pytest.raises(SUITE.GuestError):
        SUITE.validate_run(run, jobs, 'a' * 40)


def test_nonhosted_execution_refused_before_storage(tmp_path, monkeypatch):
    target = tmp_path / 'must-not-exist'
    monkeypatch.setattr(sys, 'platform', 'win32')
    monkeypatch.setattr(sys, 'argv', ['with_images.py', '--run', '123', '--directory', str(target),
                                    '--evidence', str(tmp_path / 'evidence')])
    with pytest.raises(SUITE.GuestError, match='Fresh hosted Linux root'):
        SUITE.main()
    assert not target.exists() and not (tmp_path / 'evidence').exists()


def test_public_evidence_export_does_not_change_private_file_ownership(tmp_path, monkeypatch):
    (tmp_path / 'native').mkdir()
    public = tmp_path / 'deployment-result.json'
    public.write_text('{"passed":false}')
    private = tmp_path / 'native/private-credentials.json'
    private.write_text('private fixture value')
    changed = []
    monkeypatch.setenv('SUDO_UID', '1001')
    monkeypatch.setenv('SUDO_GID', '1001')
    monkeypatch.setattr(SUITE.os, 'chown', lambda path, uid, gid: changed.append(path), raising=False)
    SUITE.publish_evidence(tmp_path)
    assert public in changed and private not in changed
    assert private.read_text() == 'private fixture value'


def test_hardlinked_outcome_is_refused_before_any_ownership_change(tmp_path, monkeypatch):
    secret = tmp_path / 'private-file'
    secret.write_text('private fixture value')
    (tmp_path / 'deployment-result.json').hardlink_to(secret)
    monkeypatch.setenv('SUDO_UID', '1001')
    monkeypatch.setenv('SUDO_GID', '1001')
    monkeypatch.setattr(SUITE.os, 'chown', lambda *args: pytest.fail('linked evidence reached ownership mutation'), raising=False)
    with pytest.raises(SUITE.GuestError, match='Linked native evidence'):
        SUITE.publish_evidence(tmp_path)


def test_failed_route_evidence_is_validated_before_becoming_readable(tmp_path, monkeypatch):
    (tmp_path / 'native').mkdir()
    (tmp_path / 'native/installed-route-failure.json').write_text(
        '{"secret":"private-value-must-not-escape"}')
    monkeypatch.setenv('SUDO_UID', '1001')
    monkeypatch.setenv('SUDO_GID', '1001')
    monkeypatch.setattr(SUITE.os, 'chown', lambda *args: pytest.fail('private data became readable'), raising=False)
    with pytest.raises(ValueError, match='Unexpected failed route evidence'):
        SUITE.publish_evidence(tmp_path)


def test_private_trust_failure_cannot_be_published_in_rotation_conditions(tmp_path, monkeypatch):
    (tmp_path/'native').mkdir()
    (tmp_path/'native/rotation-recovery-probe.json').write_text(
        '{"pending_exists":false,"pending_valid":false,"native_readable":true,'
        '"current_matches_before":false,"current_matches_after":false,"phase":"absent",'
        '"trust_sync_failure":{"available":true,"stage":"request","kind":"protocol","secret":"must-not-escape"}}')
    monkeypatch.setenv('SUDO_UID', '1001')
    monkeypatch.setenv('SUDO_GID', '1001')
    monkeypatch.setattr(SUITE.os, 'chown', lambda *args: pytest.fail('private trust metadata became readable'), raising=False)
    with pytest.raises(ValueError, match='Unexpected trust failure metadata'):
        SUITE.publish_evidence(tmp_path)
