"""The focused native diagnostic stays diagnostic only and leaves the acceptance path untouched."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[3]
ACCEPTANCE = ROOT / 'agents/opnsense/acceptance'
sys.path.insert(0, str(ACCEPTANCE))
try:
    def load(name):
        spec = importlib.util.spec_from_file_location('focus_test_' + name, ACCEPTANCE / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    FOCUS = load('focus')
    IMAGES = load('with_images')
    BOOTSTRAP = load('bootstrap')
finally:
    sys.path.pop(0)

GuestError = FOCUS.GuestError
MARK = ' # focus-guard'
# Content hashes of the acceptance-path files at the commit this feature branched from.
COMPOSE_SHA256 = '9260acb142b698527b7b0ef9cbe6e2366ed9ed41996cc85fa86e94755f3f79d8'
RELAY_SHA256 = 'cc6a6bd7f412230dd237c9f42ab90c39fa6308d7ad33412694fdedb7fa41479e'
GIT_ENV = {'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.com', 'GIT_COMMITTER_NAME': 't',
           'GIT_COMMITTER_EMAIL': 't@example.com', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull}


def sha256(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def stripped(path):
    lines = path.read_text(encoding='utf-8').split('\n')
    return '\n'.join(line for line in lines if not line.endswith(MARK))


def git(directory, *arguments):
    return subprocess.run(['git', '-C', str(directory), *arguments], check=True, capture_output=True,
                          env={**os.environ, **GIT_ENV}).stdout.decode().strip()


def covered(path, entries):
    return any(path == entry or path.startswith(entry.rstrip('/') + '/') for entry in entries)


# ---- the compared image inputs ------------------------------------------------------------

def test_image_paths_cover_every_docker_context_input():
    includes = [path for path in FOCUS.IMAGE_PATHS if not path.startswith(':')]
    allowed = [line[1:] for line in (ROOT / '.dockerignore').read_text().splitlines() if line.startswith('!')]
    for path in allowed:
        path = path.removesuffix('/**').rstrip('/')
        # A bare ancestor such as deploy/ only admits the files below it.
        assert covered(path, includes) or any(entry.startswith(path + '/') for entry in includes), path
    sources = set()
    for dockerfile in [ROOT / 'deploy/Dockerfile', *sorted((ROOT / 'deploy/images').glob('*/Dockerfile'))]:
        for line in dockerfile.read_text().splitlines():
            parts = line.split()
            if parts and parts[0] == 'COPY' and not any(part.startswith('--from') for part in parts):
                sources.update(part for part in parts[1:-1] if not part.startswith('--'))
        assert covered(dockerfile.relative_to(ROOT).as_posix(), includes)
    assert sources, 'COPY inventory unexpectedly empty'
    for source in sources:
        assert covered(source.rstrip('/'), includes), source
    assert covered('.dockerignore', includes) and covered('deploy/Dockerfile', includes)


def test_only_non_image_test_harness_files_are_excluded():
    excluded = [path for path in FOCUS.IMAGE_PATHS if path.startswith(':(exclude)')]
    assert excluded == [':(exclude)server/tests/*.py', ':(exclude)server/tests/*.sh', ':(exclude)server/tests/*.md']
    tracked = subprocess.run(['git', '-C', str(ROOT), 'ls-files', 'server/tests'], capture_output=True)
    if tracked.returncode == 0 and tracked.stdout:
        names = tracked.stdout.decode().split()
    else:
        names = [path.relative_to(ROOT).as_posix() for path in (ROOT / 'server/tests').rglob('*') if path.is_file()]
    # Everything that could be compiled or embedded in an image stays compared.
    for name in names:
        if not name.endswith(('.py', '.sh', '.md')) and '__pycache__' not in name:
            assert name.endswith('.go'), name


COMPOSE_FIXTURE = '''set -eu
stage=$(mktemp -d)
docker build -f deploy/Dockerfile -t "$image" .
native_setup_phase frps_smoke
echo middle
if [ -n "${NETHUB_IMAGE_EVIDENCE:-}" ]; then
    docker image save -o x "$image"
    echo 'Saved only tested immutable images and checksums'
fi
'''


def repository(tmp_path):
    directory = tmp_path / 'repo'
    for name in ('.dockerignore', 'LICENSE', 'NOTICE', 'deploy/Dockerfile', 'deploy/images/caddy/main.go',
                 'server/cmd/main.go', 'server/tests/compose.sh', 'server/tests/helper.py',
                 'server/tests/oidcfixture/main.go', 'agents/opnsense/acceptance/enrolled.py'):
        (directory / name).parent.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text(COMPOSE_FIXTURE if name == 'server/tests/compose.sh' else 'original\n')
    git(directory, 'init', '-q')
    git(directory, 'add', '-A')
    git(directory, 'commit', '-q', '-m', 'image source')
    return directory, git(directory, 'rev-parse', 'HEAD')


def commit_change(directory, name, text='changed\n'):
    (directory / name).parent.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(text)
    git(directory, 'add', '-A')
    git(directory, 'commit', '-q', '-m', 'change ' + name)


@pytest.mark.parametrize('name', ['.dockerignore', 'LICENSE', 'NOTICE', 'deploy/Dockerfile', 'deploy/images/caddy/main.go',
                                  'server/cmd/main.go', 'server/cmd/new.go', 'server/tests/oidcfixture/main.go',
                                  '.github/workflows/ci.yml'])
def test_any_image_input_difference_is_refused(tmp_path, name):
    directory, image = repository(tmp_path)
    FOCUS.require_identical_image_paths(directory, image)
    commit_change(directory, name)
    with pytest.raises(GuestError, match='differs from the tested images'):
        FOCUS.require_identical_image_paths(directory, image)


@pytest.mark.parametrize('name', ['server/tests/helper.py', 'server/tests/recovery/x.py',
                                  'agents/opnsense/acceptance/enrolled.py', '.github/workflows/native-focus.yml'])
def test_harness_and_acceptance_changes_keep_the_images_reusable(tmp_path, name):
    directory, image = repository(tmp_path)
    commit_change(directory, name)
    FOCUS.require_identical_image_paths(directory, image)


def test_compose_changes_outside_the_build_and_export_sections_keep_the_images_reusable(tmp_path):
    directory, image = repository(tmp_path)
    commit_change(directory, 'server/tests/compose.sh', COMPOSE_FIXTURE.replace('echo middle', 'echo other # focus-guard\necho more'))
    FOCUS.require_identical_image_paths(directory, image)


@pytest.mark.parametrize('old, new', [
    ('docker build -f deploy/Dockerfile', 'docker build --no-cache -f deploy/Dockerfile'),
    ('docker image save -o x', 'docker image save -o y'),
    ('stage=$(mktemp -d)\n', 'stage=$(mktemp -d)\nexport X=1\n')])
def test_changed_image_build_or_export_steps_are_refused(tmp_path, old, new):
    directory, image = repository(tmp_path)
    commit_change(directory, 'server/tests/compose.sh', COMPOSE_FIXTURE.replace(old, new))
    with pytest.raises(GuestError, match='Image build steps differ'):
        FOCUS.require_identical_image_paths(directory, image)


def test_a_harness_without_the_build_markers_is_refused(tmp_path):
    directory, image = repository(tmp_path)
    commit_change(directory, 'server/tests/compose.sh', 'nothing\n')
    with pytest.raises(GuestError, match='section'):
        FOCUS.require_identical_image_paths(directory, image)


def test_the_real_compose_sections_are_found_and_guards_do_not_change_them():
    text = (ROOT / 'server/tests/compose.sh').read_text()
    sections = FOCUS.compose_image_sections(text)
    assert 'docker build --target backup' in sections[0] and 'docker image save' in sections[1]
    assert not any(FOCUS.GUARD in line for part in sections for line in part.split('\n'))
    # Pinned to the ac6de06 build/export sections without reading Git history
    # (CI checkouts are shallow).
    assert hashlib.sha256('\x00'.join(sections).encode()).hexdigest() == (
        'a854f8a6d37be483987db49073276a852a7cd04aa7b0064901f76b2fff59421e')


@pytest.mark.parametrize('guarded', ['docker tag nethub-runtime:local other # focus-guard',
                                     'native_focus=wan # focus-guard', 'true # focus-guard'])
def test_only_structural_guards_may_appear_inside_an_image_section(guarded):
    text = (ROOT / 'server/tests/compose.sh').read_text()
    first = FOCUS.COMPOSE_SECTIONS[0][0]
    altered = text.replace(first, first + guarded + '\n', 1)
    with pytest.raises(GuestError, match='Unexpected focus guard'):
        FOCUS.compose_image_sections(altered)


def test_unavailable_or_malformed_image_commit_is_refused(tmp_path):
    directory, _ = repository(tmp_path)
    with pytest.raises(GuestError):
        FOCUS.require_identical_image_paths(directory, 'a' * 40)
    for value in ('HEAD', 'A' * 40, 'a' * 39, None):
        with pytest.raises(GuestError):
            FOCUS.require_identical_image_paths(directory, value)


# ---- the request ----------------------------------------------------------------------------

@pytest.mark.parametrize('text', [
    '{"image_run": "123", "focus": "wan"}', '{"focus":"wan","image_run":"9999999999999999999"}'])
def test_exact_request_is_accepted(tmp_path, text):
    path = tmp_path / 'request.json'
    path.write_text(text)
    assert FOCUS.read_request(path)[1] == 'wan'


@pytest.mark.parametrize('text', [
    '', '[]', '{}', '{"image_run": "123"}', '{"focus": "wan"}',
    '{"image_run": "123", "focus": "wan", "extra": "x"}',
    '{"image_run": 123, "focus": "wan"}', '{"image_run": "0123", "focus": "wan"}',
    '{"image_run": "12a", "focus": "wan"}', '{"image_run": "-1", "focus": "wan"}',
    '{"image_run": "123 ", "focus": "wan"}', '{"image_run": "123\\n", "focus": "wan"}',
    '{"image_run": "123456789012345678901", "focus": "wan"}', '{"image_run": "", "focus": "wan"}',
    '{"image_run": "123", "focus": "all"}', '{"image_run": "123", "focus": "WAN"}', '{"image_run": "123", "focus": ""}',
    '{"image_run": "123", "focus": "wan", "focus": "wan"}', '{"image_run": "٣", "focus": "wan"}',
    '{"image_run": "123", "focus": "wan"} trailing', '{"image_run": "123", "focus": ["wan"]}'])
def test_malformed_or_extended_request_is_refused(tmp_path, text):
    path = tmp_path / 'request.json'
    path.write_text(text, encoding='utf-8')
    with pytest.raises(GuestError):
        FOCUS.read_request(path)


def test_linked_or_oversized_request_is_refused(tmp_path):
    target = tmp_path / 'real.json'
    target.write_text('{"image_run": "123", "focus": "wan"}')
    link = tmp_path / 'link.json'
    link.symlink_to(target)
    with pytest.raises(GuestError):
        FOCUS.read_request(link)
    target.write_text('{"image_run": "123", "focus": "wan", "x": "' + 'a' * 300 + '"}')
    with pytest.raises(GuestError):
        FOCUS.read_request(target)


def test_both_trigger_paths_feed_the_same_validation(tmp_path, monkeypatch):
    output = tmp_path / 'output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    request = tmp_path / 'request.json'
    request.write_text('{"image_run": "42", "focus": "wan"}')
    monkeypatch.setattr(sys, 'argv', ['focus.py', '--request-file', str(request), '--resolve-output'])
    FOCUS.main()
    monkeypatch.setattr(sys, 'argv', ['focus.py', '--run', '42', '--focus', 'wan', '--resolve-output'])
    FOCUS.main()
    assert output.read_text() == 'image_run=42\nfocus=wan\n' * 2
    for argv in (['--run', '4 2', '--focus', 'wan'], ['--run', '42', '--focus', 'all'],
                 ['--request-file', str(request), '--run', '42'], ['--run', '42']):
        monkeypatch.setattr(sys, 'argv', ['focus.py', *argv, '--resolve-output'])
        with pytest.raises(GuestError):
            FOCUS.main()
    assert output.read_text() == 'image_run=42\nfocus=wan\n' * 2


def hosted(monkeypatch, tmp_path, event='push', ref='refs/heads/diag/native-focus/a', focus='wan'):
    monkeypatch.setattr(sys, 'platform', 'linux')
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    for key, value in dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', GITHUB_EVENT_NAME=event,
                           GITHUB_REF=ref, NETHUB_NATIVE_FOCUS=focus, NETHUB_SOURCE_HEAD='b' * 40,
                           SUDO_UID='1000', SUDO_GID='1000', GITHUB_REPOSITORY='KazuhaHub/nethub').items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(os, 'chown', lambda *arguments: None)
    monkeypatch.setattr(sys, 'argv', ['focus.py', '--run', '77', '--focus', 'wan',
                                      '--directory', str(tmp_path / 'private'), '--evidence', str(tmp_path / 'evidence')])


@pytest.mark.parametrize('change', [
    dict(event='pull_request'), dict(event='schedule'), dict(ref='refs/heads/main'),
    dict(ref='refs/heads/diag/native-focus'), dict(focus='')])
def test_unrequested_event_ref_or_focus_is_refused_before_storage(tmp_path, monkeypatch, change):
    hosted(monkeypatch, tmp_path, **change)
    with pytest.raises(GuestError, match='Fresh hosted Linux root'):
        FOCUS.main()
    assert not (tmp_path / 'private').exists() and not (tmp_path / 'evidence').exists()


def test_dispatch_is_not_bound_to_a_branch_name(tmp_path, monkeypatch):
    hosted(monkeypatch, tmp_path, event='workflow_dispatch', ref='refs/heads/main')
    monkeypatch.setattr(FOCUS, 'invoke', lambda *arguments, **keywords: (_ for _ in ()).throw(GuestError('stop')))
    with pytest.raises(GuestError, match='stop'):
        FOCUS.main()
    assert (tmp_path / 'evidence' / 'focus-result.json').exists()


def run_with_metadata(tmp_path, monkeypatch, metadata, jobs):
    hosted(monkeypatch, tmp_path)
    calls = []

    def invoke(arguments, label, **keywords):
        calls.append(list(arguments))
        if arguments[:2] == ['git', '-C'] and arguments[3] == 'rev-parse':
            return b'b' * 40 + b'\n'
        if arguments[:2] == ['gh', 'api'] and arguments[2].endswith('/runs/77'):
            return json.dumps(metadata).encode()
        if arguments[:3] == ['gh', 'run', 'view']:
            return json.dumps({'jobs': jobs}).encode()
        raise AssertionError('Unexpected command after refused provenance: ' + ' '.join(arguments))

    monkeypatch.setattr(FOCUS, 'invoke', invoke)
    monkeypatch.setattr(FOCUS, 'require_identical_image_paths', lambda *arguments: calls.append('paths'))
    return calls


def good_run():
    run = {'head_sha': 'a' * 40, 'event': 'push', 'head_repository': {'full_name': 'KazuhaHub/nethub'},
           'repository': {'full_name': 'KazuhaHub/nethub'},
           'path': '.github/workflows/ci.yml', 'status': 'completed', 'conclusion': 'success'}
    return run, [dict(name=name, status='completed', conclusion='success') for name in sorted(IMAGES.JOBS)]


@pytest.mark.parametrize('mutation', ['repository', 'path', 'conclusion', 'status', 'head', 'missing_job',
                                      'failed_job', 'extra_job', 'not_json_object', 'fork', 'event', 'no_head_repository'])
def test_exact_six_job_ci_is_still_required(tmp_path, monkeypatch, mutation):
    run, jobs = good_run()
    if mutation == 'repository':
        run['repository'] = {'full_name': 'someone/nethub'}
    elif mutation == 'path':
        run['path'] = '.github/workflows/other.yml'
    elif mutation in ('conclusion', 'status'):
        run[mutation] = 'failure' if mutation == 'conclusion' else 'in_progress'
    elif mutation == 'head':
        run['head_sha'] = 'A' * 40
    elif mutation == 'fork':
        run['event'] = 'pull_request'
        run['head_repository'] = {'full_name': 'someone/nethub'}
    elif mutation == 'event':
        run['event'] = 'workflow_dispatch'
    elif mutation == 'no_head_repository':
        del run['head_repository']
    elif mutation == 'missing_job':
        jobs.pop()
    elif mutation == 'failed_job':
        jobs[0]['conclusion'] = 'failure'
    elif mutation == 'extra_job':
        jobs.append(dict(name='extra', status='completed', conclusion='success'))
    else:
        run = []
    calls = run_with_metadata(tmp_path, monkeypatch, run, jobs)
    expected = ('Image run must come from this repository' if mutation in ('fork', 'event', 'no_head_repository')
                else 'Exact-source successful six-job CI required')
    with pytest.raises(GuestError, match=expected):
        FOCUS.main()
    assert 'paths' not in calls
    assert not any(call[:3] == ['gh', 'run', 'download'] for call in calls if call != 'paths')
    result = json.loads((tmp_path / 'evidence/focus-result.json').read_text())
    assert result['acceptance'] is False and result['diagnostic_only'] is True and result['completed'] is False
    assert result['image_paths_identical'] is False


def test_accepted_ci_checks_the_image_paths_before_any_artifact_work(tmp_path, monkeypatch):
    run, jobs = good_run()
    calls = run_with_metadata(tmp_path, monkeypatch, run, jobs)
    monkeypatch.setattr(FOCUS, 'require_identical_image_paths',
                        lambda *arguments: (_ for _ in ()).throw(GuestError('Image-affecting source differs from the tested images')))
    with pytest.raises(GuestError, match='differs from the tested images'):
        FOCUS.main()
    assert not any(isinstance(call, list) and 'download' in call for call in calls)
    result = json.loads((tmp_path / 'evidence/focus-result.json').read_text())
    assert result['image_sha'] == 'a' * 40 and result['image_paths_identical'] is False
    assert result['owned_image_cleanup_confirmed'] is True


# ---- wrapped evidence ------------------------------------------------------------------------

def wan_recovery_record():
    from wan_recovery import FLAGS, LIMITS
    value = {key: True for key in FLAGS}
    value.update({key: False for key in LIMITS})
    value.update(version=3, passed=True, phase='completed', limit_ms=60000, change_ms=100, restore_ms=200,
                 restore_attempted=True, restore_succeeded=True, failure_reason=None,
                 restore_failure_reason=None, failure_ssh_kind=None, restore_ssh_kind=None)
    return value


def wan_settling_record():
    value = dict.fromkeys(('elapsed_ms', 'stable_ms', 'samples', 'missing_route_samples', 'not_ready_samples',
                           'window_max_gap_ms'), 0)
    value.update(version=1, passed=True, phase='completed', limit_ms=60000, required_stable_ms=15000,
                 maximum_sample_gap_ms=1000, read_only_observation=True,
                 network_or_package_operation_replayed=False, public_or_release_accepted=False,
                 elapsed_ms=16000, stable_ms=15500, samples=20, window_max_gap_ms=900)
    return value


PROBE = {'passed': True, 'phase': 'complete', 'failure': '', 'http_status': 200, 'verify_code': 0,
         'default_CA_file_available': False, 'default_CA_directory_available': True}


def test_records_used_here_are_valid_and_their_wrappers_are_not():
    from wan_recovery import validate as recovery
    from wan_settling import validate as settling
    from console_probe import validate_result as probe
    from compose_tail import validate as tail
    samples = ((wan_recovery_record(), recovery), (wan_settling_record(), settling), (PROBE, probe),
               ({'version': 1, 'phase': 'completed', 'passed': True}, tail))
    for record, validator in samples:
        validator(record)
        with pytest.raises(ValueError):
            validator(FOCUS.wrap('wan', record))


def test_wrappers_are_never_public_acceptance_evidence(tmp_path, monkeypatch):
    assert not any(name.startswith('focus-') or '/focus-' in name for name in IMAGES.PUBLIC_FILES)
    (tmp_path / 'native').mkdir()
    for name, record in (('installed-wan-settling.json', wan_settling_record()),
                         ('installed-wan-identity-console.json', {'version': 1, 'collected': False}),
                         ('guest-console-probe.json', PROBE)):
        (tmp_path / 'native' / name).write_text(json.dumps(FOCUS.wrap('wan', record)))
        monkeypatch.setenv('SUDO_UID', '1000')
        monkeypatch.setenv('SUDO_GID', '1000')
        changed = []
        monkeypatch.setattr(IMAGES.os, 'chown', lambda *arguments: changed.append(arguments), raising=False)
        with pytest.raises(ValueError):
            IMAGES.publish_evidence(tmp_path)
        assert changed == []
        (tmp_path / 'native' / name).unlink()
    (tmp_path / 'focus-wan-recovery.json').write_text(json.dumps(FOCUS.wrap('wan', wan_recovery_record())))
    changed = []
    monkeypatch.setattr(IMAGES.os, 'chown', lambda *arguments: changed.append(arguments), raising=False)
    IMAGES.publish_evidence(tmp_path)
    assert all('focus-' not in str(arguments[0]) for arguments in changed)


def test_validated_records_are_wrapped_and_unvalidated_or_unbounded_ones_are_rejected(tmp_path):
    native, evidence = tmp_path / 'native', tmp_path / 'evidence'
    native.mkdir()
    evidence.mkdir()
    (native / 'installed-wan-recovery.json').write_text(json.dumps(wan_recovery_record()))
    (native / 'installed-wan-settling.json').write_text(json.dumps(dict(wan_settling_record(), private='x')))
    (native / 'guest-console-probe.json').write_text(json.dumps(PROBE))
    (native / 'guest-console-after-wan-probe.json').write_text('x' * 2000)
    (native / 'compose-tail.json').write_text(json.dumps({'version': 1, 'phase': 'stack_teardown', 'passed': True}))
    (native / 'result.json').write_text(json.dumps({
        'passed': False, 'diagnostic_only': True, 'acceptance': False, 'focus': 'wan', 'phase': 'native_page',
        'failure': 'x', 'image': {'private': 'must not be copied'}, 'guest_diagnostic': {'private': 'x'}}))
    rejected = []
    FOCUS.collect_evidence(native, evidence, 'wan', rejected)
    assert sorted(path.name for path in evidence.iterdir()) == [
        'focus-console-probe.json', 'focus-native-result.json', 'focus-wan-recovery.json']
    assert sorted(rejected) == ['compose-tail.json', 'guest-console-after-wan-probe.json', 'installed-wan-settling.json']
    for path in evidence.iterdir():
        value = json.loads(path.read_text())
        assert set(value) == {'diagnostic_only', 'acceptance', 'focus', 'record'}
        assert value['diagnostic_only'] is True and value['acceptance'] is False and value['focus'] == 'wan'
    assert json.loads((evidence / 'focus-native-result.json').read_text())['record'] == {
        'passed': False, 'phase': 'native_page', 'failure': 'x'}


def test_repository_identity_is_a_constant_not_the_sudo_environment(monkeypatch):
    # sudo --preserve-env does not carry GITHUB_REPOSITORY; the check must not depend on it.
    monkeypatch.delenv('GITHUB_REPOSITORY', raising=False)
    FOCUS.require_same_repository_run({'event': 'push', 'head_repository': {'full_name': 'KazuhaHub/nethub'}})
    monkeypatch.setenv('GITHUB_REPOSITORY', 'attacker/fork')
    FOCUS.require_same_repository_run({'event': 'push', 'head_repository': {'full_name': 'KazuhaHub/nethub'}})
    with pytest.raises(GuestError, match='this repository'):
        FOCUS.require_same_repository_run({'event': 'pull_request', 'head_repository': {'full_name': 'attacker/fork'}})


@pytest.mark.parametrize('tail', [None, {'phase': 'completed', 'passed': False}, {'phase': 'stack_teardown', 'passed': True},
                                  {'phase': 'completed'}, {'phase': 'completed', 'passed': 1}])
def test_a_successful_child_exit_still_requires_the_completed_compose_tail(tail):
    with pytest.raises(GuestError, match='completion proof'):
        FOCUS.require_completed_tail(tail)
    FOCUS.require_completed_tail({'version': 1, 'phase': 'completed', 'passed': True})


def test_result_json_is_projected_before_the_size_bound(tmp_path, monkeypatch):
    native, evidence = tmp_path / 'native', tmp_path / 'evidence'
    native.mkdir()
    evidence.mkdir()
    record = {'passed': False, 'diagnostic_only': True, 'acceptance': False, 'focus': 'wan', 'phase': 'x',
              'guest_diagnostic': {'private': 'p' * 30000}}
    (native / 'result.json').write_text(json.dumps(record))
    rejected = []
    FOCUS.collect_evidence(native, evidence, 'wan', rejected)
    assert rejected == []
    assert json.loads((evidence / 'focus-native-result.json').read_text())['record'] == {'passed': False, 'phase': 'x'}
    (evidence / 'focus-native-result.json').unlink()
    record['guest_diagnostic'] = {'private': 'p' * 70000}
    (native / 'result.json').write_text(json.dumps(record))
    FOCUS.collect_evidence(native, evidence, 'wan', rejected)
    assert rejected == ['result.json'] and not (evidence / 'focus-native-result.json').exists()
    rejected.clear()
    (native / 'result.json').write_text(json.dumps(dict(record, guest_diagnostic={})))
    monkeypatch.setattr(FOCUS, 'PROJECTION_LIMIT', 10)
    FOCUS.collect_evidence(native, evidence, 'wan', rejected)
    assert rejected == ['result.json']


def test_a_bootstrap_result_without_the_focus_marks_is_never_wrapped():
    for value in ({'passed': True}, {'passed': True, 'diagnostic_only': True, 'acceptance': True, 'focus': 'wan'},
                  {'passed': True, 'diagnostic_only': True, 'acceptance': False, 'focus': 'all'}):
        with pytest.raises(ValueError):
            FOCUS.validate_bootstrap_result(value)


# ---- the workflow ----------------------------------------------------------------------------

def workflow(name):
    return (ROOT / '.github/workflows' / name).read_text(encoding='utf-8')


def test_workflow_triggers_and_permissions_are_closed():
    text = workflow('native-focus.yml')
    head = text.split('\njobs:')[0]
    assert re.search(r'^on:\n  push:\n    branches:\n      - diag/native-focus/\*\*\n  workflow_dispatch:\n', head, re.M)
    assert 'pull_request' not in text and 'schedule' not in text and 'workflow_run' not in text
    assert re.findall(r'^  (\w+):$', head.split('\non:')[1].split('\npermissions')[0], re.M) == ['push', 'workflow_dispatch']
    assert '\npermissions: {}\n' in text
    assert 'actions: read\n      contents: read' in text and text.count('permissions:') == 2
    assert 'group: native-focus-${{ github.ref }}' in text
    assert 'timeout-minutes: 40' in text and text.count('runs-on:') == 1 and 'runs-on: ubuntu-24.04' in text
    assert 'persist-credentials: false' in text
    assert 'image_run:' in head and 'focus:' in head and 'options:\n          - wan' in head


def test_only_focus_wrappers_are_uploaded_under_a_distinct_name():
    text = workflow('native-focus.yml')
    assert text.count('actions/upload-artifact@') == 1
    step = text.split('actions/upload-artifact@')[1]
    assert 'path: ${{ runner.temp }}/native-focus-evidence/focus-*.json\n' in step
    assert step.count('path:') == 1 and 'retention-days: 3' in step
    assert 'name: native-focus-diagnostic-${{ steps.request.outputs.focus }}' in step
    assert 'if: always()' in text.split('actions/upload-artifact@')[0].rsplit('- name:', 1)[1]
    enrolled = workflow('native-enrolled.yml')
    assert 'name: installed-native-rotation' in enrolled and 'native-focus-diagnostic' not in enrolled


def test_request_and_focus_are_read_only_by_the_focus_workflow():
    for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
        text = path.read_text(encoding='utf-8')
        if path.name == 'native-focus.yml':
            assert 'native-focus-request.json' in text and 'NETHUB_NATIVE_FOCUS' in text
        else:
            assert 'native-focus-request' not in text and 'NETHUB_NATIVE_FOCUS' not in text, path.name
    for path in ACCEPTANCE.glob('*.py'):
        if path.name not in ('focus.py', 'with_images.py', 'bootstrap.py', 'enrolled.py'):
            assert 'native-focus-request' not in path.read_text(encoding='utf-8'), path.name
    for path in (ROOT / 'server/tests').glob('*'):
        if path.is_file() and path.name not in ('compose.sh', 'relay-deployment.py', 'test_native_focus.py'):
            assert 'native-focus-request' not in path.read_text(encoding='utf-8', errors='ignore'), path.name


def test_acceptance_workflow_cannot_receive_a_focus():
    text = workflow('native-focus.yml')
    run = text.split('Run the focused diagnostic')[1]
    assert 'NETHUB_NATIVE_FOCUS' in run and 'focus.py' in run and 'with_images.py' not in text


def test_acceptance_entry_point_refuses_a_focus(tmp_path, monkeypatch):
    target = tmp_path / 'must-not-exist'
    monkeypatch.setenv('NETHUB_NATIVE_FOCUS', 'wan')
    monkeypatch.setattr(sys, 'argv', ['with_images.py', '--run', '123', '--directory', str(target),
                                    '--evidence', str(tmp_path / 'evidence')])
    with pytest.raises(IMAGES.GuestError, match='never acceptance'):
        IMAGES.main()
    assert not target.exists() and not (tmp_path / 'evidence').exists()
    monkeypatch.setenv('NETHUB_NATIVE_FOCUS', '')
    with pytest.raises(IMAGES.GuestError, match='never acceptance'):
        IMAGES.main()


# ---- the acceptance path is unchanged ---------------------------------------------------------

def test_compose_without_the_focus_markers_is_the_original_byte_for_byte():
    assert sha256(stripped(ROOT / 'server/tests/compose.sh')) == COMPOSE_SHA256


def test_relay_deployment_without_the_focus_markers_is_the_original_byte_for_byte():
    assert sha256(stripped(ROOT / 'server/tests/relay-deployment.py')) == RELAY_SHA256


def test_compose_focus_markers_are_balanced_and_refuse_unknown_focus():
    lines = (ROOT / 'server/tests/compose.sh').read_text().split('\n')
    guards = [line for line in lines if line.endswith(MARK)]
    assert guards.count('if [ -z "$native_focus" ]; then' + MARK) == 8
    assert guards.count('fi' + MARK) == 9 and guards.count('else' + MARK) == 1
    text = '\n'.join(guards)
    assert "'') ;;" in text and 'wan) [ "${NETHUB_NATIVE_TEST:-0}" = 1 ]' in text and '*) echo' in text
    # Kept, never guarded: the acceptance-relevant steps of the focused run.
    unguarded = '\n'.join(line for line in lines if not line.endswith(MARK))
    for kept in ('native_setup_phase stack_start', 'native_setup_phase administrator', 'native_setup_phase relay',
                 'native_setup_phase native_guest', 'native_tail_phase stack_teardown', 'native_tail_phase completed',
                 'official/frpc', 'console-ca.pem', 'native_tail_phase runtime_log_scan'):
        assert kept in unguarded
    focus_call = [line for line in guards if 'bootstrap.py' in line]
    assert len(focus_call) == 1 and '--focus "$native_focus"' in focus_call[0] and focus_call[0].count('\\') == 0
    assert '--focus' not in unguarded


def test_relay_focus_stop_is_inside_the_try_and_after_the_verified_tunnels():
    text = (ROOT / 'server/tests/relay-deployment.py').read_text()
    tree = ast.parse(text)
    tries = [node for node in tree.body if isinstance(node, ast.Try) and node.finalbody]
    assert len(tries) == 1
    body = tries[0].body
    stops = [index for index, node in enumerate(body) if isinstance(node, ast.If)
             and isinstance(node.test, ast.Name) and node.test.id == 'focus']
    assert len(stops) == 1
    previous, following = body[stops[0] - 1], body[stops[0] + 1]
    assert 'Both legitimate assigned subdomains' in ast.unparse(previous)
    assert ast.unparse(following).startswith('exercise_traffic(')
    assert 'stop_client' in ast.unparse(tries[0].finalbody[0])


def function(tree, name):
    return next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)


def test_enrolled_changes_only_pass_the_focus_to_one_early_return():
    tree = ast.parse((ACCEPTANCE / 'enrolled.py').read_text())
    uses = [(function_node.name, node) for function_node in ast.walk(tree) if isinstance(function_node, ast.FunctionDef)
            for node in ast.walk(function_node) if isinstance(node, ast.Name) and node.id == 'focus']
    assert sorted(name for name, _ in uses) == ['_exercise', 'exercise']
    exercise, inner = function(tree, 'exercise'), function(tree, '_exercise')
    for node in (exercise, inner):
        assert [argument.arg for argument in node.args.args][-1] == 'focus' and node.args.defaults[-1].value is None
    calls = [node for node in ast.walk(exercise) if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == '_exercise']
    assert len(calls) == 1 and [getattr(argument, 'id', None) for argument in calls[0].args][-2:] == ['cleanup', 'focus']
    focused = [index for index, node in enumerate(inner.body) if isinstance(node, ast.If)
               and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name) and node.test.left.id == 'focus']
    assert len(focused) == 1
    branch = inner.body[focused[0]]
    assert len(branch.body) == 1 and isinstance(branch.body[0], ast.Return) and not branch.orelse
    assert [type(op) for op in branch.test.ops] == [ast.Eq] and branch.test.comparators[0].value == 'wan'
    refusal = inner.body[focused[0] - 1]
    assert isinstance(refusal, ast.If) and 'refuse(' in ast.unparse(refusal)
    assert 'exercise_package_migration' in ast.unparse(inner.body[focused[0] + 1])
    returned = branch.body[0].value
    fields = {key.value: value for key, value in zip(returned.keys, returned.values)}
    assert [value.value for key, value in fields.items() if isinstance(value, ast.Constant)] == [True, True, False, 'wan', True]
    assert fields['diagnostic_only'].value is True and fields['acceptance'].value is False
    assert fields['installed_wan_recovery'].id == 'wan_recovery' and fields['installed_wan_settling'].id == 'wan_settling'


def test_bootstrap_focus_defaults_to_none_and_the_baseline_branch_is_unchanged_without_it(tmp_path, monkeypatch):
    text = (ACCEPTANCE / 'bootstrap.py').read_text()
    assert "parser.add_argument('--focus', choices=('wan',), default=None)" in text
    tree = ast.parse(text)
    branches = [node for node in ast.walk(tree) if isinstance(node, ast.If)
                and 'prepare_package_baseline' in ast.unparse(node.body[0])]
    assert len(branches) == 1
    assert ast.unparse(branches[0].test) == 'args.deployment_stage is not None and args.focus is None'
    monkeypatch.setattr(sys, 'argv', ['bootstrap.py', '--directory', str(tmp_path / 'a'),
                                    '--evidence', str(tmp_path / 'b'), '--focus', 'wan'])
    with pytest.raises(BOOTSTRAP.GuestError, match='complete owned deployment binding'):
        BOOTSTRAP.main()
    assert not (tmp_path / 'a').exists()
    monkeypatch.setattr(sys, 'argv', ['bootstrap.py', '--directory', 'a', '--evidence', 'b', '--focus', 'all'])
    with pytest.raises(SystemExit):
        BOOTSTRAP.main()


# ---- copied orchestration is pinned to its source --------------------------------------------

def try_body(path):
    tree = ast.parse(path.read_text())
    main = function(tree, 'main')
    tries = [node for node in main.body if isinstance(node, ast.Try) and node.finalbody]
    assert len(tries) == 1
    return tries[0]


class Timeout(ast.NodeTransformer):
    def visit_Constant(self, node):
        return ast.copy_location(ast.Constant(value=1200), node) if node.value == 2700 else node


def assigned(node, name):
    target = node.targets[0] if isinstance(node, ast.Assign) else None
    return (isinstance(target, ast.Name) and target.id == name) or (
        isinstance(target, ast.Subscript) and ast.unparse(target) == name)


def span(body, first, last):
    start = next(index for index, node in enumerate(body) if assigned(node, first))
    end = next(index for index, node in enumerate(body) if index >= start and assigned(node, last))
    return [ast.dump(node) for node in body[start:end + 1]]


def fragments(path, normalize=False):
    tried = try_body(path)
    body = tried.body
    withs = [node for node in body if isinstance(node, ast.With)]
    assert len(withs) == 1
    with_node = Timeout().visit(withs[0]) if normalize else withs[0]
    tails = [node for node in body if isinstance(node, ast.Try) and 'read_phase' in ast.unparse(node)]
    assert len(tails) == 1
    cleanup = [node for node in tried.finalbody if isinstance(node, ast.If) and ast.unparse(node.test) == 'suite is not None']
    assert len(cleanup) == 1
    return {'source': span(body, 'head', "result['source_head']"),
            'provenance': span(body, 'metadata', 'jobs'),
            'artifact': span(body, 'artifacts', "result['artifact_id']"),
            'environment': span(body, 'environment', 'environment') + [
                ast.dump(node) for node in body if isinstance(node, ast.For)
                and ast.unparse(node.iter) in ("('GH_TOKEN', 'GITHUB_TOKEN')", 'images')],
            'child': ast.dump(with_node), 'tail': [ast.dump(handler) for handler in tails[0].handlers], 'cleanup': ast.dump(cleanup[0])}


def test_copied_orchestration_matches_the_acceptance_source():
    accepted = fragments(ACCEPTANCE / 'with_images.py', normalize=True)
    focused = fragments(ACCEPTANCE / 'focus.py')
    assert accepted.keys() == focused.keys()
    for name in accepted:
        assert accepted[name] == focused[name], 'Copied fragment drifted from with_images.py: ' + name


def test_copied_fragments_are_not_empty_and_the_pin_detects_drift(tmp_path):
    accepted = fragments(ACCEPTANCE / 'with_images.py', normalize=True)
    assert len(accepted['artifact']) >= 12 and len(accepted['source']) == 4 and len(accepted['provenance']) == 2
    assert len(accepted['environment']) == 3
    text = (ACCEPTANCE / 'focus.py').read_text().replace("'accepted image load'", "'changed image load'")
    drifted = tmp_path / 'focus_drift.py'
    drifted.write_text(text)
    assert fragments(drifted)['artifact'] != accepted['artifact']


def test_focus_reuses_the_acceptance_helpers_rather_than_copying_them():
    assert FOCUS.validate_run is sys.modules['with_images'].validate_run
    source = (ACCEPTANCE / 'focus.py').read_text()
    assert 'def validate_run' not in source and 'from with_images import validate_run' in source
    assert 'NETHUB_RECOVERY_TEST=\'0\'' in source and "NETHUB_NATIVE_FOCUS=args.focus" in source
    assert 'child.wait(timeout=1200)' in source


# ---- every test the harness and CI run against compose.sh and relay-deployment.py --------------

def invoked_tests():
    names = set()
    for path in (ROOT / 'server/tests/compose.sh', ROOT / '.github/workflows/ci.yml'):
        names.update(re.findall(r'python3 (?:"\$root/|(?:\./)?)(server/tests/test_[a-z0-9_]+\.py)', path.read_text()))
    return sorted(names)


def source_reading_tests():
    found = []
    for path in sorted((ROOT / 'server/tests').rglob('test_*.py')):
        text = path.read_text(encoding='utf-8')
        if 'compose.sh' in text or 'relay-deployment.py' in text:
            found.append(path.relative_to(ROOT).as_posix())
    return found


def test_every_test_that_reads_the_shell_or_relay_source_is_invoked_and_listed():
    reading = source_reading_tests()
    assert {'server/tests/test_image_scans.py'} <= set(reading)
    assert set(reading) <= set(invoked_tests()) | {'server/tests/test_native_focus.py'}


@pytest.mark.parametrize('name', ['server/tests/test_compose_boundaries.py', 'server/tests/test_image_scans.py'])
def test_slicing_tests_pass_against_the_guarded_compose_script(name):
    assert name in invoked_tests()
    result = subprocess.run([sys.executable, '-B', str(ROOT / name)], capture_output=True, text=True, timeout=120,
                            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    assert result.returncode == 0, result.stderr[-2000:]


def test_the_slices_those_tests_extract_are_valid_shell():
    shell = '/bin/sh'
    source = (ROOT / 'server/tests/compose.sh').read_text()
    slices = {
        'definition': source[source.index('compose_for() ('):source.index('cleanup() {')],
        'repeat': source[source.index('repeat_status=0'):source.index('python3 - "$stage"', source.index('repeat_status=0'))],
    }
    start = source.index('if [ "${NETHUB_SCAN_IMAGES:-0}" = 1 ]; then\n')
    slices['scan'] = source[start:source.index('\nnative_setup_phase frps_smoke\n', start)]
    for name, text in slices.items():
        result = subprocess.run([shell, '-n'], input=text, capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, (name, result.stderr)
    assert subprocess.run([shell, '-n', str(ROOT / 'server/tests/compose.sh')], timeout=20).returncode == 0
