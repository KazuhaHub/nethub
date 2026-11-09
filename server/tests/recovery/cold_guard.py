"""Independently reap the nonce-owned operation and destroy its private disks.

This file is copied into the root-owned control namespace before its timer is
armed. Cleanup has no repository imports, does not require the driver to survive,
and preserves unexpected units, resource bindings and paths.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import secrets


ENVIRONMENT = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'HOME': '/root', 'LANG': 'C', 'LC_ALL': 'C',
               'DOCKER_HOST': 'unix:///var/run/docker.sock'}


class GuardError(Exception):
    """Only fixed guard diagnostics may leave this private program."""


def control_identity(control):
    if (sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise GuardError('Fresh root hosted cleanup required')
    if (control != control.resolve(strict=True) or control.parent != Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
            or re.fullmatch('nethub-cold-recovery-[a-f0-9]{16}', control.name) is None):
        raise GuardError('Owned cold cleanup control required')
    info = control.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise GuardError('Private cold cleanup control refused')
    return control.name.removeprefix('nethub-cold-recovery-')


def protected(path, maximum=128 * 1024):
    info = path.lstat()
    if (path != path.resolve(strict=True) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= maximum):
        raise GuardError('Private guard file refused')
    return path.read_bytes()


def read_json(path):
    return json.loads(protected(path))


def save_once(path, value):
    if path.exists():
        if read_json(path) != value:
            raise GuardError('Original guard receipt differs')
        return
    temporary = path.parent / ('.' + path.name + '-' + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            json.dump(value, output, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def valid_state(value, nonce):
    try:
        return (isinstance(value, dict) and set(value) == {'version', 'nonce', 'source_head', 'guard_sha256', 'witness_sha256'}
                and type(value['version']) is int and value['version'] == 1 and value['nonce'] == nonce
                and re.fullmatch('[a-f0-9]{40}', value['source_head']) is not None
                and all(re.fullmatch('[a-f0-9]{64}', value[name]) is not None for name in ('guard_sha256', 'witness_sha256')))
    except (KeyError, TypeError):
        return False


def command(control, args, *, check=True, timeout=45, hosted_context=False):
    environment = dict(ENVIRONMENT)
    if hosted_context:
        control_identity(control)
        environment.update(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', RUNNER_TEMP=str(control.parent))
    if args[0] == 'docker':
        args = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', *args[1:]]
    try:
        result = subprocess.run(args, env=environment, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise GuardError('Owned cleanup operation unavailable or timed out') from None
    descriptor = os.open(control / 'guard-private.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'ab') as output:
        output.write(result.stdout + result.stderr)
    if check and result.returncode:
        raise GuardError('Owned cleanup operation failed; private state retained')
    return result


def property_value(control, unit, name):
    return command(control, ['/usr/bin/systemctl', 'show', unit, '--property=' + name, '--value']).stdout.decode().strip()


def stop_operation(control, nonce):
    unit = control.name + '.service'
    if property_value(control, unit, 'LoadState') == 'not-found':
        return
    if (property_value(control, unit, 'Description') != 'NetHub isolated cold recovery ' + nonce
            or property_value(control, unit, 'KillMode') != 'control-group'):
        raise GuardError('Operation unit ownership changed; preserved')
    group = property_value(control, unit, 'ControlGroup')
    if group and group != '/system.slice/' + unit:
        raise GuardError('Operation cgroup binding changed; preserved')
    command(control, ['/usr/bin/systemctl', 'stop', unit], timeout=50)
    if property_value(control, unit, 'ActiveState') not in ('inactive', 'failed'):
        raise GuardError('Owned operation still active')
    if group:
        path = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
        if path.exists() and 'populated 0' not in path.read_text().splitlines():
            raise GuardError('Owned operation cgroup still contains processes')


def remove_owned_directory(path, parent):
    if not path.exists() and not path.is_symlink():
        return
    info = path.lstat()
    if (path != path.resolve(strict=True) or path.parent != parent or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700
            or path.stat().st_dev != parent.stat().st_dev or os.path.ismount(path)
            or not shutil.rmtree.avoids_symlink_attacks):
        raise GuardError('Owned private removal boundary differs; preserved')
    shutil.rmtree(path)
    if path.exists() or path.is_symlink():
        raise GuardError('Owned private namespace remains')


def witness_pointer(value, parent):
    if not isinstance(value, dict) or set(value) != {'version', 'control'} or type(value['version']) is not int or value['version'] != 1:
        raise GuardError('Original witness ownership record refused')
    path = Path(value['control'])
    if (not path.is_absolute() or path != path.resolve() or path.parent != parent
            or re.fullmatch('nethub-cold-witness-[a-f0-9]{16}', path.name) is None):
        raise GuardError('Owned witness pointer boundary differs; preserved')
    return path


def absent_resource(control, kind, name):
    result = command(control, ['docker', kind, 'inspect', name], check=False)
    if not result.returncode:
        raise GuardError('Uninitialized witness has a resource; preserved')
    command(control, ['docker', 'info', '--format', '{{.ID}}'])
    if b'no such' not in result.stderr.lower() and b'not found' not in result.stderr.lower():
        raise GuardError('Witness resource absence not established')


def witness_absent(control, witness):
    nonce = witness.name.removeprefix('nethub-cold-witness-')
    for unit in (witness.name + '.service', 'nethub-cold-witness-guard-' + nonce + '.timer',
                 'nethub-cold-witness-guard-' + nonce + '.service'):
        load = property_value(control, unit, 'LoadState')
        if load != 'not-found' and property_value(control, unit, 'ActiveState') not in ('inactive', 'failed'):
            raise GuardError('Witness unit still active; private namespace preserved')
    absent_resource(control, 'container', 'nethub-acme-test-' + nonce)
    absent_resource(control, 'network', 'nethub-acme-test-' + nonce + '-network')


def clean_witness(control, state):
    record = control / 'witness.json'
    if not record.exists():
        if record.is_symlink():
            raise GuardError('Witness ownership record is aliased')
        return False
    witness = witness_pointer(read_json(record), control.parent)
    nonce = witness.name.removeprefix('nethub-cold-witness-')
    binding = hashlib.sha256(str(witness).encode()).hexdigest()
    receipt = {'version': 1, 'witness_control_fingerprint': binding,
               'owned_witness_resources_and_private_namespace_removed': True}
    saved = control / 'witness-cleanup.json'
    prepared = control / 'witness-removal-prepared.json'
    intent = {'version': 1, 'witness_control_fingerprint': binding, 'resource_cleanup_confirmed_before_removal': True}
    if not witness.exists():
        if witness.is_symlink():
            raise GuardError('Removed witness path became an alias')
        if saved.exists():
            if read_json(saved) != receipt:
                raise GuardError('Original witness cleanup proof differs')
            return True
        if read_json(prepared) != intent:
            raise GuardError('Missing witness has no original cleanup proof')
        witness_absent(control, witness)
        save_once(saved, receipt)
        return True
    info = witness.lstat()
    if (witness != witness.resolve(strict=True) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
        raise GuardError('Witness control ownership differs; preserved')
    if prepared.exists():
        if read_json(prepared) != intent:
            raise GuardError('Original witness removal preparation differs')
        witness_absent(control, witness)
    elif (witness / 'state.json').exists():
        program = witness / 'cleanup.py'
        if hashlib.sha256(protected(program)).hexdigest() != state['witness_sha256']:
            raise GuardError('Witness cleanup program differs; preserved')
        command(control, ['/usr/bin/python3', '-I', str(program), str(witness)], timeout=150, hosted_context=True)
        expected = {'owned_CA_and_process_group_removed': True, 'temporary_witness_keys_removed': True,
                    'full_host_recovery_accepted': False}
        if read_json(witness / 'cleanup.json') != expected:
            raise GuardError('Witness resource cleanup not confirmed')
        guard = 'nethub-cold-witness-guard-' + nonce
        # The associated transient service must execute this exact protected
        # program before the outer guard may disarm its timer.
        if property_value(control, guard + '.service', 'LoadState') != 'not-found':
            if str(program) not in property_value(control, guard + '.service', 'ExecStart'):
                raise GuardError('Witness guard program binding differs; preserved')
        for suffix in ('.timer', '.service'):
            unit = guard + suffix
            if property_value(control, unit, 'LoadState') != 'not-found':
                if suffix == '.timer' and property_value(control, unit, 'Unit') != guard + '.service':
                    raise GuardError('Witness guard association differs; preserved')
                command(control, ['/usr/bin/systemctl', 'stop', unit], timeout=50)
                if property_value(control, unit, 'ActiveState') not in ('inactive', 'failed'):
                    raise GuardError('Witness guard remains active')
    else:
        # Publication precedes all witness resources. A cut before state/program
        # installation is removable only after independently proving absence.
        for unit in (witness.name + '.service', 'nethub-cold-witness-guard-' + nonce + '.timer',
                     'nethub-cold-witness-guard-' + nonce + '.service'):
            if property_value(control, unit, 'LoadState') != 'not-found':
                raise GuardError('Uninitialized witness has a unit; preserved')
        absent_resource(control, 'container', 'nethub-acme-test-' + nonce)
        absent_resource(control, 'network', 'nethub-acme-test-' + nonce + '-network')
    save_once(prepared, intent)
    remove_owned_directory(witness, control.parent)
    save_once(saved, receipt)
    return True


def cleanup(control):
    import fcntl

    nonce = control_identity(control)
    state = read_json(control / 'guard-state.json')
    if not valid_state(state, nonce) or hashlib.sha256(protected(control / 'cold_guard.py')).hexdigest() != state['guard_sha256']:
        raise GuardError('Original guard program or state differs')
    descriptor = os.open(control / 'guard.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0):
            raise GuardError('Private outer cleanup lease refused')
        fcntl.flock(lock, fcntl.LOCK_EX)
        stop_operation(control, nonce)
        witnessed = clean_witness(control, state)
        remove_owned_directory(control / 'private', control)
        receipt = {'version': 1, 'source_head': state['source_head'],
                   'operation_cgroup_reaped': True, 'owned_private_VM_disks_keys_and_logs_removed': True,
                   'owned_witness_removed_or_never_started': True, 'witness_was_started': witnessed,
                   'full_recovery_or_goal_accepted': False}
        save_once(control / 'guard-cleanup.json', receipt)
        return receipt


if __name__ == '__main__':
    os.umask(0o077)
    try:
        if len(sys.argv) != 2:
            raise GuardError('Owned cleanup control path required')
        cleanup(Path(sys.argv[1]))
    except Exception:
        raise SystemExit('Owned cold cleanup failed; guard and private state retained') from None
