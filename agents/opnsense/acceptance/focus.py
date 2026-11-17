"""Run one focused native diagnostic against an earlier source's tested images.

Diagnostic only, never acceptance: the full workflow in with_images.py remains the only
acceptance path, and it refuses to run while NETHUB_NATIVE_FOCUS is set.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import importlib.util

from guest import GuestError, invoke, validate_read_only_inspection_recoveries
from compose_tail import read_phase
from compose_tail import validate as validate_compose_tail
from compose_setup import inspect as inspect_setup
from compose_setup import project as project_setup
from wan_recovery import validate as validate_wan_recovery
from wan_settling import validate as validate_wan_settling
from wan_identity_console import validate as validate_wan_identity_console
from console_probe import validate_result as validate_console_probe
from post_wan_failure import validate as validate_post_wan_failure
from with_images import validate_run


ROOT = Path(__file__).resolve().parents[3]
FOCI = ('wan',)
REQUEST_FILE = '.github/native-focus-request.json'
BRANCH_PREFIX = 'refs/heads/diag/native-focus/'
# Every tracked path that can change the five tested images (see .dockerignore and the
# COPY sources of deploy/Dockerfile and deploy/images/*/Dockerfile). The excluded
# harness files are never copied into a final image layer; Go test fixtures stay included.
IMAGE_PATHS = ('.dockerignore', 'LICENSE', 'NOTICE', 'deploy/Dockerfile', 'deploy/images', 'server',
               ':(exclude)server/tests/*.py', ':(exclude)server/tests/*.sh', ':(exclude)server/tests/*.md',
               '.github/workflows/ci.yml')
GUARD = ' # focus-guard'
REPOSITORY = 'KazuhaHub/nethub'
COMPOSE = 'server/tests/compose.sh'
# The parts of compose.sh that build, scan and export the tested images; the focus guards are
# removed first so a guarded HEAD compares equal to the unguarded source of the tested run.
COMPOSE_SECTIONS = (('stage=$(mktemp -d)\n', '\nnative_setup_phase frps_smoke\n'),
                    ('if [ -n "${NETHUB_IMAGE_EVIDENCE:-}" ]; then\n', "\n    echo 'Saved only tested immutable images"))
PROJECTION_LIMIT = 16384
RUN_PATTERN = r'[1-9][0-9]{0,19}'


def validate_values(run, focus):
    if (not isinstance(run, str) or re.fullmatch(RUN_PATTERN, run) is None
            or not isinstance(focus, str) or focus not in FOCI):
        raise GuestError('A digit-only image run and a known focus are required')
    return run, focus


def read_request(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 256:
        raise GuestError('Unexpected native focus request file')

    def unique(pairs):
        keys = [key for key, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError('duplicate key')
        return dict(pairs)

    try:
        value = json.loads(path.read_bytes().decode('ascii'), object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise GuestError('Unreadable native focus request') from None
    if not isinstance(value, dict) or set(value) != {'image_run', 'focus'}:
        raise GuestError('Native focus request must contain exactly image_run and focus')
    return validate_values(value['image_run'], value['focus'])


def require_identical_image_paths(root, image_sha):
    """Refuse unless the image-affecting source is byte-identical to the tested images' source."""
    if not isinstance(image_sha, str) or re.fullmatch(r'[a-f0-9]{40}', image_sha) is None:
        raise GuestError('Exact image source identity required')
    invoke(['git', '-C', str(root), 'cat-file', '-e', image_sha + '^{tree}'], 'tested image source availability')
    result = subprocess.run(['git', '-C', str(root), 'diff', '--quiet', '--no-renames', image_sha, 'HEAD',
                             '--', *IMAGE_PATHS], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
    if result.returncode == 1:
        raise GuestError('Image-affecting source differs from the tested images')
    if result.returncode:
        raise GuestError('Image source comparison failed')
    require_identical_compose_sections(root, image_sha)


# Only these exact structural guard lines may appear inside a compared image
# section; any other guarded line there could hide an image-changing step.
STRUCTURAL_GUARDS = frozenset(('if [ -z "$native_focus" ]; then', 'fi'))


def compose_image_sections(text):
    sections = []
    for first, last in COMPOSE_SECTIONS:
        if text.count(first) != 1:
            raise GuestError('Image build section of the Compose harness not found')
        start = text.index(first)
        end = text.find(last, start)
        if end < 0:
            raise GuestError('Image build section of the Compose harness not found')
        kept = []
        for line in text[start:end].split('\n'):
            if line.endswith(GUARD):
                if line[:-len(GUARD)].strip() not in STRUCTURAL_GUARDS:
                    raise GuestError('Unexpected focus guard inside an image build section')
                continue
            kept.append(line)
        sections.append('\n'.join(kept))
    return sections


def require_identical_compose_sections(root, image_sha):
    texts = []
    for revision in (image_sha, 'HEAD'):
        shown = subprocess.run(['git', '-C', str(root), 'show', revision + ':' + COMPOSE],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
        if shown.returncode:
            raise GuestError('Image build section comparison failed')
        texts.append(compose_image_sections(shown.stdout.decode('utf-8')))
    if texts[0] != texts[1]:
        raise GuestError('Image build steps differ from the tested images')


def require_same_repository_run(metadata):
    """The image run must come from a push or a same-repository pull request, never a fork."""
    head = metadata.get('head_repository')
    if (metadata.get('event') not in ('push', 'pull_request') or not isinstance(head, dict)
            or head.get('full_name') != REPOSITORY):
        raise GuestError('Image run must come from this repository, not a fork')


def require_completed_tail(tail):
    if not isinstance(tail, dict) or tail.get('passed') is not True or tail.get('phase') != 'completed':
        raise GuestError('Focused native completion proof missing')


def validate_bootstrap_result(value):
    """Project only closed fields of the bootstrap result for a focused run."""
    if (not isinstance(value, dict) or value.get('diagnostic_only') is not True
            or value.get('acceptance') is not False or value.get('focus') not in FOCI
            or type(value.get('passed')) is not bool):
        raise ValueError('Unexpected focused bootstrap result')
    projection = {'passed': value['passed']}
    for key in ('phase', 'failure'):
        if key in value:
            text = value[key]
            if not isinstance(text, str) or len(text) > 200 or not text.isascii() or not text.isprintable():
                raise ValueError('Unexpected focused bootstrap text')
            projection[key] = text
    if 'installed_rotation' in value:
        rotation = value['installed_rotation']
        if (not isinstance(rotation, dict) or set(rotation) != {
                'passed', 'diagnostic_only', 'acceptance', 'focus', 'installed_wan_recovery',
                'installed_wan_settling', 'console_after_wan_passed'}
                or rotation['passed'] is not True or rotation['diagnostic_only'] is not True
                or rotation['acceptance'] is not False or rotation['focus'] not in FOCI
                or rotation['console_after_wan_passed'] is not True):
            raise ValueError('Unexpected focused installed outcome')
        validate_wan_recovery(rotation['installed_wan_recovery'])
        validate_wan_settling(rotation['installed_wan_settling'])
        projection['installed_rotation'] = rotation
    if 'read_only_inspection_recoveries' in value:
        validate_read_only_inspection_recoveries(value['read_only_inspection_recoveries'])
        projection['read_only_inspection_recoveries'] = value['read_only_inspection_recoveries']
    return projection


def checked(validator):
    def project(value):
        validator(value)
        return value
    return project


# (native file, focus file, size bound, validator returning the record to wrap)
EVIDENCE = (
    ('installed-wan-recovery.json', 'focus-wan-recovery.json', 8192, checked(validate_wan_recovery)),
    ('installed-wan-settling.json', 'focus-wan-settling.json', 2048, checked(validate_wan_settling)),
    ('installed-wan-identity-console.json', 'focus-wan-identity-console.json', 2048,
     checked(validate_wan_identity_console)),
    ('guest-console-probe.json', 'focus-console-probe.json', 1024, checked(validate_console_probe)),
    ('guest-console-after-wan-probe.json', 'focus-console-after-wan-probe.json', 1024,
     checked(validate_console_probe)),
    ('post-wan-console-failure.json', 'focus-post-wan-failure.json', 2048, checked(validate_post_wan_failure)),
    ('compose-tail.json', 'focus-compose-tail.json', 1024, checked(validate_compose_tail)),
    ('result.json', 'focus-native-result.json', 65536, validate_bootstrap_result),
)


def wrap(focus, record):
    return {'diagnostic_only': True, 'acceptance': False, 'focus': focus, 'record': record}


def collect_evidence(native, evidence, focus, rejected):
    """Copy each bounded native record that passes its own validator into one wrapper."""
    for source, target, limit, project in EVIDENCE:
        path = native / source
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        try:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= limit:
                raise ValueError('unbounded native evidence')
            record = project(json.loads(path.read_bytes()))
            if len(json.dumps(record)) > PROJECTION_LIMIT:
                raise ValueError('unbounded projection')
            (evidence / target).write_text(json.dumps(wrap(focus, record), indent=2) + '\n', encoding='utf-8')
        except (OSError, ValueError, TypeError, KeyError):
            rejected.append(source)


def publish(evidence):
    uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
    if uid <= 0 or gid < 0:
        raise GuestError('Hosted evidence reader identity required')
    for path in sorted(evidence.glob('focus-*.json')):
        if path.is_symlink() or not path.is_file():
            raise GuestError('Linked focused evidence refused')
        os.chown(path, uid, gid)
        path.chmod(0o600)
    os.chown(evidence, uid, gid)
    evidence.chmod(0o700)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request-file', type=Path)
    parser.add_argument('--run')
    parser.add_argument('--focus')
    parser.add_argument('--resolve-output', action='store_true',
                        help='Validate the request and write image_run and focus to GITHUB_OUTPUT')
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    if args.request_file is not None:
        if args.run is not None or args.focus is not None:
            raise GuestError('One request source required')
        args.run, args.focus = read_request(args.request_file)
    else:
        validate_values(args.run, args.focus)
    if args.resolve_output:
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='ascii') as output:
            output.write('image_run=' + args.run + '\nfocus=' + args.focus + '\n')
        return
    event = os.environ.get('GITHUB_EVENT_NAME')
    if (sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or event not in ('workflow_dispatch', 'push')
            or (event == 'push' and not os.environ.get('GITHUB_REF', '').startswith(BRANCH_PREFIX))
            or os.environ.get('NETHUB_NATIVE_FOCUS') != args.focus
            or args.directory is None or args.evidence is None):
        raise GuestError('Fresh hosted Linux root and a requested focus are required')
    os.umask(0o077)
    directory, evidence = args.directory.absolute(), args.evidence.absolute()
    if directory != directory.resolve() or evidence != evidence.resolve():
        raise GuestError('Aliased native deployment storage refused')
    directory.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    result = {'diagnostic_only': True, 'acceptance': False, 'focus': args.focus, 'image_run': args.run,
              'completed': False, 'image_paths_identical': False}
    rejected = []
    images, preexisting = {}, set()
    suite = None
    try:
        head = os.environ['NETHUB_SOURCE_HEAD']
        actual = invoke(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], 'native deployment source identity').decode().strip()
        if head != actual:
            raise GuestError('Native deployment source differs')
        result['source_head'] = head
        result['phase'] = 'tested_image_provenance'
        metadata = json.loads(invoke(['gh', 'api', 'repos/KazuhaHub/nethub/actions/runs/' + args.run], 'accepted CI identity'))
        jobs = json.loads(invoke(['gh', 'run', 'view', args.run, '--repo', 'KazuhaHub/nethub', '--json', 'jobs'],
                                 'accepted CI job evidence'))['jobs']
        image_sha = metadata.get('head_sha') if isinstance(metadata, dict) else None
        if not isinstance(image_sha, str) or re.fullmatch(r'[a-f0-9]{40}', image_sha) is None:
            raise GuestError('Exact-source successful six-job CI required')
        result['image_sha'] = image_sha
        validate_run(metadata, jobs, image_sha)
        require_same_repository_run(metadata)
        result['phase'] = 'image_source_paths'
        require_identical_image_paths(ROOT, image_sha)
        result['image_paths_identical'] = True
        result['phase'] = 'tested_image_artifact'
        artifacts = json.loads(invoke(['gh', 'api', 'repos/KazuhaHub/nethub/actions/runs/' + args.run + '/artifacts?per_page=100'],
                                      'accepted image artifact identity'))
        matches = [item for item in artifacts['artifacts'] if item['name'] == 'deployment-images']
        if (artifacts['total_count'] > 100 or len(matches) != 1 or matches[0]['expired']
                or not 1 <= matches[0]['size_in_bytes'] <= 2 * 1024**3):
            raise GuestError('One bounded unexpired deployment image artifact required')
        archive = directory / 'images'
        archive.mkdir(mode=0o700)
        invoke(['gh', 'run', 'download', args.run, '--repo', 'KazuhaHub/nethub', '--name', 'deployment-images',
                '--dir', str(archive)], 'accepted image artifact download', timeout=180)
        if {path.name for path in archive.iterdir()} != {'images.tar.gz', 'images.json', 'SHA256SUMS'}:
            raise GuestError('Unexpected accepted image artifact files')
        if any(path.is_symlink() or not path.is_file() for path in archive.iterdir()):
            raise GuestError('Linked image artifact refused')
        spec = importlib.util.spec_from_file_location('native_image_policy', ROOT / 'server/tests/oidc-compose.py')
        suite = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(suite)
        result['image_phase'] = 'archive_inventory'
        images, preexisting = suite.archive_images(archive)
        result['image_phase'] = 'docker_load'
        invoke(['docker', 'load', '-i', str(archive / 'images.tar.gz')], 'accepted image load', timeout=180)
        result['image_phase'] = 'loaded_identity'
        suite.verify_loaded_images(images)
        result['image_phase'] = 'verified'
        result['tested_images'] = {name: value['id'] for name, value in images.items()}
        result['artifact_id'] = matches[0]['id']
        result['phase'] = 'focused_native_run'
        environment = dict(os.environ)
        for key in ('GH_TOKEN', 'GITHUB_TOKEN'):
            environment.pop(key, None)
        for name in images:
            variable = 'NETHUB_RUNTIME_TEST_IMAGE' if name == 'runtime' else 'NETHUB_' + name.upper() + '_TEST_IMAGE'
            environment[variable] = images[name]['tag']
        environment.update(NETHUB_NATIVE_TEST='1', NETHUB_SCAN_IMAGES='0', NETHUB_BROWSER_TEST='0',
                           NETHUB_RECOVERY_TEST='0', NETHUB_NATIVE_FOCUS=args.focus,
                           NETHUB_NATIVE_DIRECTORY=str(directory / 'native-private'),
                           NETHUB_NATIVE_EVIDENCE=str(directory / 'native-evidence'))
        with (directory / 'compose-private.log').open('xb') as log:
            child = subprocess.Popen(['sh', str(ROOT / 'server/tests/compose.sh')], env=environment,
                                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                child.wait(timeout=1200)
            except BaseException:
                # Signal only the session created above, giving the owned shell's
                # cleanup trap and its native guest a bounded termination window.
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
                raise
        native = directory / 'native-evidence'
        try:
            tail = read_phase(native)
        except (OSError, ValueError, TypeError):
            tail = None
        result['compose_tail'] = tail
        if child.returncode:
            try:
                result['compose_setup'] = inspect_setup(directory / 'compose-private.log', child.returncode)
            except (OSError, ValueError, UnicodeError):
                result['compose_setup'] = project_setup(b'', child.returncode)
            phase = tail['phase'] if tail is not None else result['compose_setup']['phase']
            raise GuestError('Focused native diagnostic failed at ' + phase)
        require_completed_tail(tail)
        outcome = validate_bootstrap_result(json.loads((native / 'result.json').read_text(encoding='utf-8')))
        rotation = outcome.get('installed_rotation')
        if (outcome['passed'] is not True or rotation is None or rotation['installed_wan_recovery']['passed'] is not True
                or rotation['installed_wan_settling']['passed'] is not True):
            raise GuestError('Focused native completion proof missing')
        result['completed'] = True
        result['phase'] = 'completed'
    except Exception as error:
        result['failure'] = str(error) if isinstance(error, GuestError) else type(error).__name__
        raise
    finally:
        cleanup = True
        if suite is not None:
            for item in images.values():
                if item['tag'] not in preexisting:
                    try:
                        suite.remove_image(item['tag'], item.get('loaded_id', item['id']))
                    except Exception:
                        cleanup = False
        result['owned_image_cleanup_confirmed'] = cleanup
        if not cleanup:
            result['completed'] = False
        collect_evidence(directory / 'native-evidence', evidence, args.focus, rejected)
        result['rejected_evidence'] = sorted(rejected)
        (evidence / 'focus-result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        publish(evidence)
    if not result['completed']:
        raise GuestError('Owned focused native diagnostic cleanup incomplete')
    print('Focused native diagnostic completed; it is not acceptance')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Focused native diagnostic failed: ' + (str(error) if isinstance(error, GuestError) else type(error).__name__), file=sys.stderr)
        raise SystemExit(1)
