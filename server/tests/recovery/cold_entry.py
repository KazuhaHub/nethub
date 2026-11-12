"""Bind hosted cold recovery to exact successful CI images and closed exports."""
import argparse
import hashlib
import gzip
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

from cold_evidence import validate_cleanup, validate_operation
from cold_guard import read_json, save_once
from cold_launcher import run as launch
from cold_operation import ROOT
from cold_witness import IMAGE
from image_archive import inspect_archive
from linux_guest import RecoveryError, invoke, sha256

sys.path.insert(0, str(ROOT / 'agents/opnsense/acceptance'))
from bootstrap import SDK, SDK_SHA256
from guest import download
from with_images import validate_run


def evidence_images(control, destination):
    source = control / 'native-evidence'
    images = {}
    for action in ('enroll', 'remove'):
        receipt = read_json(source / ('installed-' + action + '-page.json'))
        name = 'installed-' + action + '.png'
        expected = {'passed', 'action', 'expected_success', 'actual_native_write_API', 'screenshots'}
        if (set(receipt) != expected or receipt['passed'] is not True or receipt['action'] != action
                or receipt['expected_success'] is not True or receipt['actual_native_write_API'] is not True
                or set(receipt['screenshots']) != {name}):
            raise RecoveryError('Exact native page evidence required')
        path = source / name
        info = path.lstat()
        if (path != path.resolve(strict=True) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != 0 or not 1 <= info.st_size <= 2 * 1024**2):
            raise RecoveryError('Bounded original masked native image required')
        digest = sha256(path)
        if receipt['screenshots'][name] != digest:
            raise RecoveryError('Original masked native image hash differs')
        with (destination / name).open('xb') as output:
            output.write(path.read_bytes())
        images[name] = digest
    return images


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--witness-binary', type=Path, required=True)
    args = parser.parse_args()
    head = os.environ.get('NETHUB_SOURCE_HEAD', '')
    if (sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or re.fullmatch('[a-f0-9]{40}', head) is None or re.fullmatch('[1-9][0-9]{0,19}', args.run) is None):
        raise RecoveryError('Exact source and accepted hosted image run required')
    os.umask(0o077)
    parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    for path in (args.directory, args.evidence):
        if path != path.resolve() or path.parent != parent:
            raise RecoveryError('New direct private hosted workspace required')
        path.mkdir(mode=0o700)
    result = {'version': 1, 'source_head': head, 'accepted_ci_run': int(args.run), 'passed': False,
              'phase': 'image_provenance', 'operation': None, 'cleanup': None, 'screenshots': {},
              'artifact_id': None, 'image_archive_sha256': None, 'full_goal_complete': False}
    try:
        metadata = json.loads(invoke(['gh', 'api', 'repos/KazuhaHub/nethub/actions/runs/' + args.run], 'Exact producer run'))
        jobs = json.loads(invoke(['gh', 'run', 'view', args.run, '--repo', 'KazuhaHub/nethub', '--json', 'jobs'],
                                 'Exact six producer jobs'))['jobs']
        validate_run(metadata, jobs, head)
        artifacts = json.loads(invoke(['gh', 'api', 'repos/KazuhaHub/nethub/actions/runs/' + args.run + '/artifacts?per_page=100'],
                                      'Exact producer artifacts'))
        matches = [item for item in artifacts['artifacts'] if item['name'] == 'deployment-images']
        if artifacts['total_count'] > 100 or len(matches) != 1 or matches[0]['expired'] or not 0 < matches[0]['size_in_bytes'] <= 2 * 1024**3:
            raise RecoveryError('One bounded unexpired exact-source image archive required')
        archive = args.directory / 'images'
        archive.mkdir(mode=0o700)
        invoke(['gh', 'run', 'download', args.run, '--repo', 'KazuhaHub/nethub', '--name', 'deployment-images', '--dir', str(archive)],
               'Exact-source image archive download', timeout=180)
        if {p.name for p in archive.iterdir()} != {'images.tar.gz', 'images.json', 'SHA256SUMS'} or any(p.is_symlink() or not p.is_file() for p in archive.iterdir()):
            raise RecoveryError('Exact image artifact files required')
        spec = importlib.util.spec_from_file_location('cold_image_archive_policy', ROOT / 'server/tests/oidc-compose.py')
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        result['image_phase'] = 'archive_inventory'
        images, _ = policy.archive_images(archive)
        tags = {role: item['tag'] for role, item in images.items()}
        result['image_phase'] = 'archive_expansion'
        expanded = args.directory / 'images.tar'
        total = 0
        with gzip.open(archive / 'images.tar.gz', 'rb') as compressed, expanded.open('xb') as output:
            while block := compressed.read(1024 * 1024):
                total += len(block)
                if total > 2 * 1024**3:
                    raise RecoveryError('Expanded producer image archive exceeds bound')
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        result['image_phase'] = 'archive_content'
        inspected = inspect_archive(expanded)
        result['image_phase'] = 'producer_identity'
        if set(inspected) != set(tags.values()):
            raise RecoveryError('Exact five archived image tags required')
        for item in images.values():
            if (inspected[item['tag']]['config'] != item['id']
                    or inspected[item['tag']]['layers'] != item['diff_ids']):
                raise RecoveryError('Actual archived image differs from producer manifest')
        result['image_phase'] = 'verified'
        result.update(artifact_id=matches[0]['id'], image_archive_sha256=sha256(archive / 'images.tar.gz'))
        result['phase'] = 'pinned_inputs'
        sdk = args.directory / SDK
        download('https://go.dev/dl/' + SDK, sdk, 128 * 1024**2)
        if sha256(sdk) != SDK_SHA256:
            raise RecoveryError('Pinned appliance compiler differs')
        invoke(['docker', 'pull', IMAGE], 'Pinned independent CA image', timeout=180)
        result['phase'] = 'guarded_operation'
        control, operation, cleanup = launch(ROOT, expanded, tags, sdk, args.witness_binary,
                                             ownership_record=args.directory / 'operation-control.json')
        result['operation'] = validate_operation(operation, head)
        result['cleanup'] = validate_cleanup(cleanup, head)
        result['screenshots'] = evidence_images(control, args.evidence)
        result.update(passed=True, phase='completed')
    finally:
        record = args.directory / 'operation-control.json'
        if record.exists() and result['operation'] is None:
            pointer = read_json(record)
            control = Path(pointer['control'])
            if (set(pointer) != {'version', 'control'} or pointer['version'] != 1 or control.parent != parent
                    or control != control.resolve(strict=True) or re.fullmatch('nethub-cold-recovery-[a-f0-9]{16}', control.name) is None):
                raise RecoveryError('Original operation pointer refused')
            if (control / 'operation-result.json').exists():
                result['operation'] = validate_operation(read_json(control / 'operation-result.json'), head)
            if (control / 'guard-cleanup.json').exists():
                result['cleanup'] = validate_cleanup(read_json(control / 'guard-cleanup.json'), head)
        save_once(args.evidence / 'result.json', result)
        uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
        if uid <= 0 or gid < 0:
            raise RecoveryError('Hosted artifact reader identity required')
        for path in args.evidence.iterdir():
            if path.name not in ('result.json', 'installed-enroll.png', 'installed-remove.png') or not path.is_file() or path.is_symlink():
                raise RecoveryError('Unexpected public cold evidence file')
            os.chown(path, uid, gid)
            path.chmod(0o600)
        os.chown(args.evidence, uid, gid)
        args.evidence.chmod(0o700)
    if result['passed'] is not True:
        raise RecoveryError('Isolated cold recovery did not pass')
    print('Full isolated protected-host recovery and native initial issuance passed; public operator and durable custody remain separate')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Isolated cold recovery failed; inspect closed evidence') from None
