"""Bind a fresh native/Compose run to the same source's accepted image archive."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

from guest import GuestError, invoke


ROOT = Path(__file__).resolve().parents[3]
JOBS = {'workflow lint', 'Go vulnerability checks', 'weekend0 kit checks',
        'OPNsense plugin checks', 'Control plane checks', 'Deployment checks'}
PUBLIC_FILES = ('deployment-result.json', 'native/result.json', 'native/installed-rotation.json',
                'native/native-fixture-host.json',
                'native/installed-enroll-page.json', 'native/installed-rotate-page.json',
                'native/installed-enroll.png', 'native/installed-rotate.png')


def publish_evidence(directory):
    uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
    if uid <= 0 or gid < 0:
        raise GuestError('Hosted evidence reader identity required')
    directories = [path for path in (directory / 'native', directory) if path.exists()]
    if any(path.is_symlink() or not path.is_dir() for path in directories):
        raise GuestError('Linked native evidence directory refused')
    files = []
    for name in PUBLIC_FILES:
        path = directory / name
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
                raise GuestError('Linked native evidence refused')
            files.append(path)
    for path in files:
        os.chown(path, uid, gid)
        path.chmod(0o600)
    for path in directories:
        os.chown(path, uid, gid)
        path.chmod(0o700)


def validate_run(run, jobs, head):
    if (not re.fullmatch(r'[a-f0-9]{40}', head) or run.get('head_sha') != head
            or run.get('repository', {}).get('full_name') != 'KazuhaHub/nethub'
            or run.get('path') != '.github/workflows/ci.yml'
            or run.get('status') != 'completed' or run.get('conclusion') != 'success'
            or len(jobs) != len(JOBS) or {job.get('name') for job in jobs} != JOBS
            or any(job.get('status') != 'completed' or job.get('conclusion') != 'success' for job in jobs)):
        raise GuestError('Exact-source successful six-job CI required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if (sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or not re.fullmatch(r'[1-9][0-9]{0,19}', args.run)):
        raise GuestError('Fresh hosted Linux root and accepted CI run required')
    os.umask(0o077)
    directory, evidence = args.directory.absolute(), args.evidence.absolute()
    if directory != directory.resolve() or evidence != evidence.resolve():
        raise GuestError('Aliased native deployment storage refused')
    directory.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    result = {'passed': False, 'scope': 'Installed native enrollment and credential rotation',
              'accepted_image_run': args.run, 'full_goal_complete': False, 'formal_release': False}
    images, preexisting = {}, set()
    suite = None
    try:
        head = os.environ['NETHUB_SOURCE_HEAD']
        actual = invoke(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], 'native deployment source identity').decode().strip()
        if head != actual:
            raise GuestError('Native deployment source differs')
        result['source_head'] = head
        result['phase'] = 'accepted_image_provenance'
        metadata = json.loads(invoke(['gh', 'api', 'repos/KazuhaHub/nethub/actions/runs/' + args.run], 'accepted CI identity'))
        jobs = json.loads(invoke(['gh', 'run', 'view', args.run, '--repo', 'KazuhaHub/nethub', '--json', 'jobs'],
                                 'accepted CI job evidence'))['jobs']
        validate_run(metadata, jobs, head)
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
        images, preexisting = suite.archive_images(archive)
        invoke(['docker', 'load', '-i', str(archive / 'images.tar.gz')], 'accepted image load', timeout=180)
        suite.verify_loaded_images(images)
        result['tested_images'] = {name: value['id'] for name, value in images.items()}
        result['artifact_id'] = matches[0]['id']
        result['phase'] = 'actual_native_and_six_service_run'
        environment = dict(os.environ)
        for key in ('GH_TOKEN', 'GITHUB_TOKEN'):
            environment.pop(key, None)
        for name in images:
            variable = 'NETHUB_RUNTIME_TEST_IMAGE' if name == 'runtime' else 'NETHUB_' + name.upper() + '_TEST_IMAGE'
            environment[variable] = images[name]['tag']
        environment.update(NETHUB_NATIVE_TEST='1', NETHUB_SCAN_IMAGES='0', NETHUB_BROWSER_TEST='0',
                           NETHUB_NATIVE_DIRECTORY=str(directory / 'native-private'),
                           NETHUB_NATIVE_EVIDENCE=str(evidence / 'native'))
        with (directory / 'compose-private.log').open('xb') as log:
            child = subprocess.Popen(['sh', str(ROOT / 'server/tests/compose.sh')], env=environment,
                                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                child.wait(timeout=1500)
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
        if child.returncode:
            raise GuestError('Owned native deployment acceptance failed')
        native = json.loads((evidence / 'native/installed-rotation.json').read_text(encoding='utf-8'))
        if native.get('passed') is not True:
            raise GuestError('Installed native rotation proof missing')
        result['installed_rotation'] = native
        result['passed'] = True
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
                        suite.remove_image(item['tag'], item['id'])
                    except Exception:
                        cleanup = False
        result['owned_image_cleanup_confirmed'] = cleanup
        if not cleanup:
            result['passed'] = False
        (evidence / 'deployment-result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        publish_evidence(evidence)
    if not result['passed']:
        raise GuestError('Owned native deployment cleanup incomplete')
    print('Installed native and six-service acceptance passed its recorded scope; full W7 remains separate')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Installed native deployment failed: ' + (str(error) if isinstance(error, GuestError) else type(error).__name__), file=sys.stderr)
        raise SystemExit(1)
