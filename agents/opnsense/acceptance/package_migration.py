"""Exercise real native package rollback/upgrade during planned owned relay outages."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import time

from guest import Guest, GuestError, invoke
from package_probe import HASHES, validate as validate_probe


ROOT = Path(__file__).resolve().parents[3]
BASELINE = 'c9e74abb1fb1c060ab32ee880d20f32d8d7a653b'
VERSIONS = ('0.0.18', '2026.48')
PROFILES = {'0.0.18': [10, 30], '2026.48': [1, 3]}
GUEST_PACKAGES = {'0.0.18': '/root/nethub-ci/package-baseline/source/agents/opnsense/plugin/dist/os-nethub-agent.pkg',
                  '2026.48': '/root/nethub-ci/source/agents/opnsense/plugin/dist/os-nethub-agent.pkg'}
PHASES = ('baseline', 'widen', 'offline_rollback', 'rollback', 'legacy_recovered', 'legacy_steady',
          'offline_upgrade', 'upgrade', 'current_recovered', 'current_steady', 'completed')
FLAGS = ('identity_GUI_trust_and_runtime_preserved', 'source_grants_unchanged',
         'both_native_package_checksums_verified', 'other_five_services_unchanged',
         'witness_original_process_retained', 'original_relay_configuration_restored',
         'current_native_package_and_profile_restored', 'normal_verified_routes_recovered')
LIMITS = ('manual_agent_start_or_reconcile', 'arbitrary_network_loss_accepted',
          'public_network_or_formal_package_accepted', 'full_W5_acceptance')
PHASE_VERSIONS = {name: ('0.0.18' if name in ('rollback', 'legacy_recovered', 'legacy_steady', 'offline_upgrade')
                         else '2026.48') for name in PHASES[:-1]}
OUTAGE_PHASES = ('offline_rollback', 'offline_upgrade')
OUTAGE_FLAGS = ('relay_running', 'native_control_present', 'native_route_verified', 'witness_route_verified')
INVARIANTS = HASHES + ('lifecycle_markers', 'gui_readback', 'witness_process')


def validate_packages(value):
    if (not isinstance(value, dict) or set(value) != {'baseline_source', 'baseline_source_archive_sha256',
            'package_sha256', 'formal_release'} or value['baseline_source'] != BASELINE
            or value['formal_release'] is not False or not isinstance(value['baseline_source_archive_sha256'], str)
            or not re.fullmatch('[a-f0-9]{64}', value['baseline_source_archive_sha256'])
            or not isinstance(value['package_sha256'], dict) or set(value['package_sha256']) != set(VERSIONS)
            or any(not isinstance(item, str) or not re.fullmatch('[a-f0-9]{64}', item)
                   for item in value['package_sha256'].values()) or len(set(value['package_sha256'].values())) != 2):
        raise ValueError('Unexpected native package build baseline')


def owned(guest):
    if (type(guest) is not Guest or guest.process is None or guest.process.poll() is not None
            or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise GuestError('Live owned hosted guest required for native package migration')


def prepare(guest, directory):
    """Build the immutable old source before enrollment starts any grant clocks."""
    owned(guest)
    directory = Path(directory)
    archive = directory / 'package-baseline.tar'
    if archive.exists() or archive.is_symlink():
        raise GuestError('Native package baseline archive already exists')
    for path, expected in [('agents/opnsense/plugin/build.sh', b'VERSION=0.0.18\n'),
                           ('server/.go-version', b'1.26.11\n'),
                           ('agents/opnsense/plugin/FRP_VERSION', b'0.71.1\n')]:
        raw = invoke(['git', '-C', str(ROOT), 'show', BASELINE + ':' + path], 'immutable old package source')
        if expected not in raw:
            raise GuestError('Old package source no longer matches the selected version/compiler')
    raw = invoke(['git', '-C', str(ROOT), '-c', 'core.autocrlf=false', 'archive', '--format=tar', BASELINE],
                 'old package source archive')
    archive.write_bytes(raw)
    archive.chmod(0o600)
    archive_hash = hashlib.sha256(raw).hexdigest()
    guest.put(archive, archive.name)
    guest.ssh('set -eu\numask 077\n'
        'test "$(sha256 -q /root/nethub-ci/package-baseline.tar)" = ' + archive_hash + '\n'
        'test ! -e /root/nethub-ci/package-baseline\nmkdir /root/nethub-ci/package-baseline\n'
        'mkdir /root/nethub-ci/package-baseline/source\n'
        'tar -xf /root/nethub-ci/package-baseline.tar -C /root/nethub-ci/package-baseline/source\n'
        'PATH=/root/nethub-ci/toolchain/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin\n'
        'export PATH\nsh /root/nethub-ci/package-baseline/source/agents/opnsense/plugin/build.sh\n',
        'immutable old native package build', timeout=1000)
    hashes = {}
    for version, path in GUEST_PACKAGES.items():
        value = guest.ssh('sha256 -q ' + path + '\n', 'native package archive checksum').decode().strip()
        if not re.fullmatch('[a-f0-9]{64}', value):
            raise GuestError('Native package archive checksum unavailable')
        hashes[version] = value
    if len(set(hashes.values())) != 2:
        raise GuestError('Old and current native packages must differ')
    result = {'baseline_source': BASELINE, 'baseline_source_archive_sha256': archive_hash,
              'package_sha256': hashes, 'formal_release': False}
    validate_packages(result)
    return result


def validate(value):
    fields = set(FLAGS + LIMITS) | {'version', 'passed', 'phase', 'baseline_source', 'current_source',
        'package_sha256', 'relay_config_sha256', 'steps', 'outages', 'cleanup_stopped_failed_relay', 'invariant_failures'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['version']) is not int or value['version'] != 3
            or type(value['passed']) is not bool or value['phase'] not in PHASES
            or value['baseline_source'] != BASELINE or not isinstance(value['current_source'], str)
            or not re.fullmatch('[a-f0-9]{40}', value['current_source'])
            or any(type(value[key]) is not bool for key in FLAGS + LIMITS + ('cleanup_stopped_failed_relay',))
            or any(value[key] for key in LIMITS) or not isinstance(value['package_sha256'], dict)
            or set(value['package_sha256']) != set(VERSIONS)
            or any(not isinstance(v, str) or not re.fullmatch('[a-f0-9]{64}', v) for v in value['package_sha256'].values())
            or len(set(value['package_sha256'].values())) != 2
            or not isinstance(value['relay_config_sha256'], str) or not re.fullmatch('[a-f0-9]{64}', value['relay_config_sha256'])
            or not isinstance(value['steps'], list) or len(value['steps']) > 10
            or not isinstance(value['outages'], list) or len(value['outages']) > 2):
        raise ValueError('Unexpected native package migration outcome')
    failures = value['invariant_failures']
    # Only fixed category names may leave the private fixture. Never include
    # compared values, fingerprints, marker names or exception text here.
    if (not isinstance(failures, list) or any(type(item) is not str or item not in INVARIANTS for item in failures)
            or failures != [name for name in INVARIANTS if name in failures]
            or value['passed'] and failures):
        raise ValueError('Unexpected native package invariant diagnosis')
    for index, outage in enumerate(value['outages']):
        if (not isinstance(outage, dict) or set(outage) != {'phase', 'profile', 'budget_ms', 'first', 'last'}
                or outage['phase'] != OUTAGE_PHASES[index]
                or not isinstance(outage['profile'], list) or len(outage['profile']) != 2
                or any(type(number) is not int for number in outage['profile'])
                or outage['profile'] != PROFILES[PHASE_VERSIONS[outage['phase']]]
                or type(outage['budget_ms']) is not int or outage['budget_ms'] != (outage['profile'][1] + 10) * 1000):
            raise ValueError('Unexpected planned package outage')
        for name in ('first', 'last'):
            observation = outage[name]
            if (not isinstance(observation, dict) or set(observation) != set(OUTAGE_FLAGS) | {'elapsed_ms'}
                    or any(type(observation[key]) is not bool for key in OUTAGE_FLAGS)
                    or type(observation['elapsed_ms']) is not int or not 0 <= observation['elapsed_ms'] <= 300000):
                raise ValueError('Unexpected planned outage observation')
        if outage['last']['elapsed_ms'] < outage['first']['elapsed_ms']:
            raise ValueError('Planned outage observation clock moved backwards')
    seen = []
    for row in value['steps']:
        if (not isinstance(row, dict) or set(row) != {'phase', 'passed', 'elapsed_ms', 'package_version',
                'profile', 'routes_verified', 'relay_running', 'same_native_process_window'}
                or row['phase'] not in PHASES[:-1] or type(row['passed']) is not bool
                or type(row['elapsed_ms']) is not int or not 0 <= row['elapsed_ms'] <= 300000
                or row['package_version'] != PHASE_VERSIONS[row['phase']]
                or not isinstance(row['profile'], list) or len(row['profile']) != 2
                or any(type(number) is not int for number in row['profile'])
                or row['profile'] != PROFILES[row['package_version']]
                or any(type(row[key]) is not bool for key in ('routes_verified', 'relay_running', 'same_native_process_window'))):
            raise ValueError('Unexpected native package migration step')
        seen.append(row['phase'])
    if seen != list(PHASES[:len(seen)]) or len(set(seen)) != len(seen):
        raise ValueError('Native package migration phases changed order')
    if value['passed']:
        if (value['phase'] != 'completed' or seen != list(PHASES[:-1]) or not all(value[key] for key in FLAGS)
                or not all(row['passed'] for row in value['steps']) or value['cleanup_stopped_failed_relay']
                or len(value['outages']) != 2 or any(outage['last']['elapsed_ms'] > outage['budget_ms']
                    or any(outage['last'][key] for key in OUTAGE_FLAGS) for outage in value['outages'])):
            raise ValueError('Incomplete native package migration success')
        for row in value['steps']:
            offline = row['phase'] in ('offline_rollback', 'rollback', 'offline_upgrade', 'upgrade')
            if row['routes_verified'] == offline or row['relay_running'] == offline:
                raise ValueError('Unmeasured planned relay outage or recovery')
        for name, minimum in [('legacy_steady', 35000), ('current_steady', 10000)]:
            row = next(row for row in value['steps'] if row['phase'] == name)
            if row['elapsed_ms'] < minimum or not row['same_native_process_window']:
                raise ValueError('Native package steady window did not retain the original control')
    elif value['phase'] == 'completed':
        raise ValueError('Failed native package migration cannot be complete')


def exercise(guest, stage, compose, evidence, nonce, packages, native_read, route,
             gui_read, check_database, witness, witness_route, witness_sockets):
    owned(guest)
    stage, evidence = Path(stage), Path(evidence)
    project = compose[3] if len(compose) > 3 else ''
    if (compose[:3] != ['docker', 'compose', '-p'] or not re.fullmatch('nethub-stack-test-[a-z0-9-]+', project)
            or stage.parent not in (Path('/tmp'), Path('/var/tmp')) or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise GuestError('Owned package migration deployment required')
    validate_packages(packages)
    return _exercise(guest, stage, compose, evidence, nonce, packages, native_read, route,
                     gui_read, check_database, witness, witness_route, witness_sockets)


def _exercise(guest, stage, compose, evidence, nonce, packages, native_read, route,
              gui_read, check_database, witness, witness_route, witness_sockets):
    """Testable orchestration; the public entry point checks ownership first."""
    project = compose[3]
    policy_spec = importlib.util.spec_from_file_location('native_package_relay_policy', ROOT / 'server/tests/relay_migration.py')
    policy = importlib.util.module_from_spec(policy_spec)
    policy_spec.loader.exec_module(policy)
    config = stage / 'deployment/secrets/frps/frps.toml'
    info = config.lstat()
    if config.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise GuestError('Regular owned relay configuration required')
    original = config.read_bytes()
    configurations = {timeout: policy.timeout_config(original, timeout) for timeout in (3, 30)}
    if configurations[3] != original:
        raise GuestError('Current relay heartbeat baseline required')
    candidate = config.with_name('frps-native-package-candidate.toml')
    result = {key: False for key in FLAGS + LIMITS}
    result.update(version=3, passed=False, phase='baseline', baseline_source=BASELINE, invariant_failures=[],
        current_source=os.environ['NETHUB_SOURCE_HEAD'], package_sha256=packages['package_sha256'],
        relay_config_sha256=hashlib.sha256(original).hexdigest(), steps=[], outages=[], cleanup_stopped_failed_relay=False)
    path = evidence / 'installed-package-migration.json'

    def save():
        validate(result)
        path.write_text(json.dumps(result, indent=2), encoding='utf-8')
        path.chmod(0o600)

    def service(role):
        identifier = invoke(compose + ['ps', '--all', '--quiet', role], 'owned migration service identity').decode().strip()
        if not re.fullmatch('[a-f0-9]{64}', identifier):
            raise GuestError('Migration service identity unavailable')
        value = json.loads(invoke(['docker', 'inspect', identifier], 'owned migration service state'))[0]
        if value['Config']['Labels'].get('com.docker.compose.project') != project or value['State']['OOMKilled']:
            raise GuestError('Migration service ownership or resources changed')
        return {'id': identifier, 'image': value['Image'], 'pid': value['State']['Pid'],
                'started': value['State']['StartedAt'], 'running': value['State']['Running']}

    services = {role: service(role) for role in ('postgres', 'nethub-web', 'nethub-authz', 'caddy', 'backup', 'frps')}
    if not all(item['running'] for item in services.values()):
        raise GuestError('All six migration services must start online')
    def probe():
        value = json.loads(guest.ssh_read_only_inspection(
            '/usr/local/bin/python3.13 /root/nethub-ci/package_probe.py ' + nonce + '\n'))
        validate_probe(value)
        return value

    before = probe()
    assignment = native_read('native-package-before-private.json')
    gui = gui_read()
    if before['package_version'] != '2026.48' or before['profile'] != [1, 3] or any(before['markers'].values()):
        raise GuestError('Clean current native package baseline required')

    def invariants(value):
        failures = [key for key in HASHES if value[key] != before[key]]
        if value['markers'] != before['markers']:
            failures.append('lifecycle_markers')
        if not failures and gui_read() != gui:
            failures.append('gui_readback')
        if not failures and witness.poll() is not None:
            failures.append('witness_process')
        if failures:
            result['invariant_failures'] = failures
            save()
            raise GuestError('Package migration changed enrollment, GUI, trust or witness process: '
                             + ', '.join(failures))
        check_database()
        for role, expected in services.items():
            current = service(role)
            if (role != 'frps' and current != expected or role == 'frps'
                    and (current['id'], current['image']) != (expected['id'], expected['image'])):
                raise GuestError('Package migration changed an unrelated service')

    def append(phase, started, value, online, steady=False):
        invariants(value)
        elapsed = time.monotonic() - started
        if not 0 <= elapsed <= 300:
            raise GuestError('Native package migration step exceeded its observation bound')
        row = {'phase': phase, 'passed': True, 'elapsed_ms': round(elapsed * 1000),
            'package_version': value['package_version'], 'profile': value['profile'], 'routes_verified': online,
            'relay_running': service('frps')['running'], 'same_native_process_window': steady}
        result['steps'].append(row)
        result['phase'] = phase
        save()

    def replace_config(raw):
        current = config.lstat()
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or config.is_symlink() or candidate.exists() or candidate.is_symlink():
            raise GuestError('Owned migration relay file changed')
        with candidate.open('xb') as output:
            os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(output.fileno(), info.st_uid, info.st_gid)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(candidate, config)

    def offline(phase):
        result['phase'] = phase
        save()
        initial = probe()
        started = time.monotonic()
        budget = initial['profile'][1] + 10
        invoke(compose + ['stop', '--timeout', '3', 'frps'], 'planned owned relay outage', timeout=20)
        outage = None
        while True:
            value = probe()
            invariants(value)
            if value['profile'] != initial['profile']:
                raise GuestError('Native heartbeat profile changed during planned outage')
            observation = {'relay_running': service('frps')['running'],
                'native_control_present': value['control_sha256'] is not None,
                'native_route_verified': bool(route()), 'witness_route_verified': bool(witness_route())}
            elapsed = time.monotonic() - started
            observation['elapsed_ms'] = round(elapsed * 1000)
            if outage is None:
                outage = {'phase': phase, 'profile': initial['profile'], 'budget_ms': budget * 1000,
                          'first': dict(observation), 'last': observation}
                result['outages'].append(outage)
            else:
                outage['last'] = observation
            save()
            # A stopped relay does not synchronously close the guest's TCP view.
            # Observe only; never replay stop, installation or reconciliation.
            if elapsed > budget:
                raise GuestError('Planned relay outage did not settle within its heartbeat observation bound')
            if not any(observation[key] for key in OUTAGE_FLAGS):
                append(phase, started, value, False)
                return
            time.sleep(.25)

    def install(version, phase):
        result['phase'] = phase
        save()
        started = time.monotonic()
        previous = probe()['process_sha256']
        guest.console.command('set -eu\ntest "$(sha256 -q ' + GUEST_PACKAGES[version] + ')" = '
            + packages['package_sha256'][version] + '\npkg add -f ' + GUEST_PACKAGES[version] + '\n', timeout=180)
        guest.ensure_ssh()
        deadline = time.monotonic() + 90
        while True:
            value = probe()
            invariants(value)
            if value['package_version'] == version and value['profile'] == PROFILES[version] and value['running']:
                if value['process_sha256'] == previous:
                    raise GuestError('Native package hooks did not replace the old client process')
                break
            if time.monotonic() >= deadline:
                raise GuestError('Native package did not converge automatically')
            time.sleep(1)
        if native_read('native-package-' + version + '-private.json') != assignment:
            raise GuestError('Native package API lost its saved assignment')
        if route() or witness_route() or service('frps')['running']:
            raise GuestError('Package transition was not performed with the relay offline')
        append(phase, started, value, False)
        return value

    def online(timeout, phase, retained=None):
        result['phase'] = phase
        save()
        started = time.monotonic()
        value = probe()
        policy.require_compatible(timeout, [tuple(value['profile']), (1, 3)])
        replace_config(configurations[timeout])
        invoke(compose + ['start', 'frps'], 'planned owned relay restart', timeout=20)
        deadline = started + 90
        while True:
            value = probe()
            invariants(value)
            if retained is not None and value['process_sha256'] != retained['process_sha256']:
                raise GuestError('Native client did not survive relay recovery')
            if time.monotonic() >= deadline:
                raise GuestError('Package migration routes did not recover')
            if value['control_sha256'] is not None and route() and witness_route() and witness_sockets():
                append(phase, started, value, True)
                return value
            time.sleep(.5)

    def steady(phase, seconds):
        result['phase'] = phase
        save()
        started = time.monotonic()
        first = probe()
        control = witness_sockets()
        while True:
            value = probe()
            invariants(value)
            if (value['process_sha256'] != first['process_sha256'] or value['control_sha256'] != first['control_sha256']
                    or value['control_sha256'] is None or witness_sockets() != control or not route() or not witness_route()):
                raise GuestError('Native package steady window lost an original control or route')
            if time.monotonic() - started >= seconds + 45:
                raise GuestError('Native package steady window exceeded its observation bound')
            if time.monotonic() - started >= seconds:
                append(phase, started, value, True, steady=True)
                return
            time.sleep(.5)

    try:
        for timeout, raw in configurations.items():
            if candidate.exists() or candidate.is_symlink():
                raise GuestError('Owned package candidate file already exists')
            with candidate.open('xb') as output:
                os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode))
                os.fchown(output.fileno(), info.st_uid, info.st_gid)
                output.write(raw)
            invoke(compose + ['exec', '-T', 'frps', '/frps', 'verify', '-c', '/run/secrets/' + candidate.name],
                   'official package migration relay configuration verification')
            candidate.unlink()
        if not before['running'] or before['control_sha256'] is None or not route() or not witness_route():
            raise GuestError('Verified native and witness baseline routes required')
        append('baseline', time.monotonic(), before, True)
        # Widen first while all known clients still use the current profile.
        invoke(compose + ['stop', '--timeout', '3', 'frps'], 'planned widening relay stop', timeout=20)
        online(30, 'widen', before)
        offline('offline_rollback')
        legacy = install('0.0.18', 'rollback')
        online(30, 'legacy_recovered', legacy)
        steady('legacy_steady', 35)
        offline('offline_upgrade')
        current = install('2026.48', 'upgrade')
        online(3, 'current_recovered', current)
        steady('current_steady', 10)
        if config.read_bytes() != original or not service('frps')['running']:
            raise GuestError('Original relay configuration was not restored')
        result.update({key: True for key in FLAGS})
        result.update(passed=True, phase='completed')
    finally:
        if not result['passed']:
            # Do not restart a short-timeout relay after an uncertain rollback.
            # The enclosing fixture destroys this guest and all owned services.
            try:
                invoke(compose + ['stop', '--timeout', '3', 'frps'], 'failed migration relay quiescence', timeout=20)
                result['cleanup_stopped_failed_relay'] = not service('frps')['running']
                if candidate.exists() and not candidate.is_symlink():
                    candidate.unlink()
                replace_config(original)
                result['original_relay_configuration_restored'] = config.read_bytes() == original
            except (GuestError, OSError, ValueError):
                pass
        save()
    return result
