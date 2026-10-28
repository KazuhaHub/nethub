"""Reject untested or differently sourced images before native acceptance."""
import copy
import importlib.util
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
