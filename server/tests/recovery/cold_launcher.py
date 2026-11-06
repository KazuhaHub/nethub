"""Launch one staged recovery operation under independent systemd cleanup.

The caller must first enforce the exact successful CI image-producer gate. This
launcher validates the selected source and staged bytes; neither check replaces
the producer gate or complete result/artifact review.
"""
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
import time

from cold_guard import (ENVIRONMENT, GuardError, cleanup, command, control_identity,
                        property_value, read_json, save_once)
from host_layout import valid_tags
from linux_guest import invoke


def stage_file(source, destination, mode, maximum):
    source = Path(source)
    info = source.lstat()
    if (source != source.resolve(strict=True) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != 0 or info.st_mode & 0o022 or not 0 < info.st_size <= maximum):
        raise GuardError('Owned staged recovery source refused')
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with source.open('rb') as original, os.fdopen(descriptor, 'wb') as output:
        opened = os.fstat(original.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise GuardError('Staged recovery source identity changed')
        shutil.copyfileobj(original, output, 1024 * 1024)
        output.flush()
        os.fsync(output.fileno())
        after = os.fstat(original.fileno())
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
            raise GuardError('Staged recovery source changed during copy')
    destination.chmod(mode)
    with destination.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(repository, images, tags, sdk, witness_binary):
    if (sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise GuardError('Fresh root hosted recovery launcher required')
    repository = Path(repository).resolve(strict=True)
    head = os.environ.get('NETHUB_SOURCE_HEAD', '')
    if re.fullmatch('[a-f0-9]{40}', head) is None or not valid_tags(tags):
        raise GuardError('Exact recovery source and five tested image tags required')
    actual = invoke(['git', '-C', str(repository), 'rev-parse', 'HEAD'], 'Launcher source identity').decode().strip()
    if actual != head:
        raise GuardError('Recovery launcher source differs')
    invoke(['git', '-C', str(repository), 'diff', '--exit-code', 'HEAD'], 'Launcher tracked clean source')
    nonce = secrets.token_hex(8)
    parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    control = parent / ('nethub-cold-recovery-' + nonce)
    control.mkdir(mode=0o700)
    control_identity(control)
    guard = 'nethub-cold-recovery-guard-' + nonce
    service = control.name + '.service'
    for unit in (service, guard + '.timer', guard + '.service'):
        if property_value(control, unit, 'LoadState') != 'not-found':
            raise GuardError('New recovery unit identity already exists')
    inputs = control / 'inputs'
    inputs.mkdir(mode=0o700)
    directory = repository / 'server/tests/recovery'
    guard_hash = stage_file(directory / 'cold_guard.py', control / 'cold_guard.py', 0o600, 128 * 1024)
    witness_hash = hashlib.sha256((directory / 'cold_witness.py').read_bytes()).hexdigest()
    save_once(control / 'guard-state.json', {'version': 1, 'nonce': nonce, 'source_head': head,
              'guard_sha256': guard_hash, 'witness_sha256': witness_hash})
    image_hash = stage_file(images, inputs / 'images.tar.gz', 0o600, 2 * 1024**3)
    stage_file(sdk, inputs / 'toolchain.tar.gz', 0o600, 128 * 1024**2)
    binary_hash = stage_file(witness_binary, inputs / 'guiacme.test', 0o555, 128 * 1024**2)
    save_once(control / 'inputs.json', {'version': 1, 'source_head': head, 'tags': tags,
              'images': str(inputs / 'images.tar.gz'), 'images_sha256': image_hash,
              'sdk': str(inputs / 'toolchain.tar.gz'), 'witness_binary': str(inputs / 'guiacme.test'),
              'witness_binary_sha256': binary_hash})
    log = control / 'operation-private.log'
    log.touch(mode=0o600, exist_ok=False)
    env = {**ENVIRONMENT, **{key: os.environ[key]
           for key in ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_TEMP', 'NETHUB_SOURCE_HEAD',
                       'NETHUB_NODE_BINARY', 'PLAYWRIGHT_BROWSERS_PATH')}}
    inherited = ['--setenv=' + key + '=' + value for key, value in env.items()]
    # No GitHub token enters either service environment. The timer runs from a
    # protected standalone copy and remains armed until cleanup is confirmed.
    command(control, ['/usr/bin/systemd-run', '--unit=' + guard, '--on-active=3600s',
                      '--property=UnsetEnvironment=GH_TOKEN GITHUB_TOKEN', *inherited,
                      '/usr/bin/python3', '-I', str(control / 'cold_guard.py'), str(control)])
    if (property_value(control, guard + '.timer', 'ActiveState') != 'active'
            or property_value(control, guard + '.timer', 'Unit') != guard + '.service'):
        raise GuardError('Independent recovery cleanup timer not active')
    result = None
    try:
        command(control, ['/usr/bin/systemd-run', '--unit=' + control.name,
            '--description=NetHub isolated cold recovery ' + nonce, '--service-type=exec',
            '--working-directory=' + str(repository), '--property=RuntimeMaxSec=3300',
            '--property=UnsetEnvironment=GH_TOKEN GITHUB_TOKEN',
            '--property=TimeoutStopSec=30', '--property=KillMode=control-group', '--property=RemainAfterExit=yes',
            '--property=StandardOutput=append:' + str(log), '--property=StandardError=append:' + str(log),
            *inherited, '/usr/bin/python3', '-B', str(directory / 'cold_operation.py'), str(control)])
        deadline = time.monotonic() + 3350
        while property_value(control, service, 'SubState') != 'exited':
            if (property_value(control, service, 'ActiveState') != 'active' or time.monotonic() >= deadline):
                raise GuardError('Guarded recovery failed or timed out; private result retained')
            time.sleep(2)
        result = read_json(control / 'operation-result.json')
        if (result.get('source_head') != head or result.get('passed') is not True
                or property_value(control, service, 'Result') != 'success'
                or property_value(control, service, 'ExecMainStatus') != '0'):
            raise GuardError('Guarded recovery actual process/result did not pass')
    finally:
        cleanup(control)
        for suffix in ('.timer', '.service'):
            unit = guard + suffix
            if property_value(control, unit, 'LoadState') != 'not-found':
                command(control, ['/usr/bin/systemctl', 'stop', unit])
                if property_value(control, unit, 'ActiveState') not in ('inactive', 'failed'):
                    raise GuardError('Independent recovery guard remains active after cleanup')
    return control, result, read_json(control / 'guard-cleanup.json')
