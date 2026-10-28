"""Bind hosted FreeBSD filesystem contracts to the exact checked-out source."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
SCOPES = ['agents/opnsense/plugin', 'agents/opnsense/tests', 'proto',
          'agents/opnsense/native_contracts.py', '.github/workflows/native-contracts.yml']
GROUPS = {
    'enrollment': (14, [
        'agents/opnsense/plugin/tests/test_certificate_enrollment.py',
        'agents/opnsense/plugin/tests/test_scheduler.py::test_enrollment_handoff_has_no_credentials_or_cached_output',
        'agents/opnsense/tests/test_enrollment.py::test_php_controller_keeps_credentials_private_and_saves_under_native_lock',
    ]),
    'service': (42, [
        'agents/opnsense/plugin/tests/test_circuit_breaker.py',
        'agents/opnsense/plugin/tests/test_service_controller.py',
        'agents/opnsense/plugin/tests/test_scheduler.py',
        'agents/opnsense/plugin/tests/test_watchdog.py',
        'agents/opnsense/plugin/tests/test_rotation_agent.py',
        'agents/opnsense/plugin/tests/test_lifecycle_agent.py::test_removal_after_unknown_rotation_commit_uses_saved_candidate',
    ]),
    'wire': (138, [
        'agents/opnsense/tests/test_protocol.py',
        'agents/opnsense/plugin/tests/test_relay_trust_backend.py',
        'agents/opnsense/tests/test_rotation_journal.py',
        'agents/opnsense/tests/test_rotation_backend.py',
        'agents/opnsense/tests/test_rotation_native_store.py',
        'agents/opnsense/tests/test_rotation_transaction.py',
        'agents/opnsense/tests/test_rotation_trust_binding.py',
    ]),
}
REQUIRED_NATIVE_CASES = {'test_enrollment_lock_interoperates_with_native_scheduler_lockf',
                         'test_native_lockf_excludes_both_python_operations'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def source_matches(root, files):
    if not isinstance(files, dict) or not 1 <= len(files) <= 2000:
        return False
    for name, expected in files.items():
        if (not isinstance(name, str) or '\\' in name or not name
                or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                or str(PurePosixPath(name)) != name
                or not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{64}', expected)):
            return False
        path = root / name
        if (not path.is_file() or path.is_symlink() or path.resolve() != root.resolve().joinpath(name)
                or digest(path.read_bytes()) != expected):
            return False
    return True


def read_manifest(directory, expected_head, expected_digest):
    raw = (directory / 'source.json').read_bytes()
    if len(raw) > 1024 * 1024 or digest(raw) != expected_digest:
        raise ValueError('Source manifest mismatch')
    value = json.loads(raw)
    if (set(value) != {'version', 'source_head', 'files'} or value['version'] != 1
            or not re.fullmatch(r'[a-f0-9]{40}', expected_head)
            or value['source_head'] != expected_head or not source_matches(ROOT, value['files'])):
        raise ValueError('Source binding mismatch')
    return value


def prepare(directory, expected_head):
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r'[a-f0-9]{40}', expected_head) or head != expected_head:
        raise ValueError('Unexpected checked-out source')
    subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--', *SCOPES], cwd=ROOT, check=True, capture_output=True)
    paths = subprocess.check_output(['git', 'ls-files', '-z', '--', *SCOPES], cwd=ROOT).decode().split('\0')
    files = {name: digest((ROOT / name).read_bytes()) for name in paths if name}
    for required in ['agents/opnsense/native_contracts.py', '.github/workflows/native-contracts.yml']:
        if required not in files:
            raise ValueError('Incomplete source manifest')
    if not source_matches(ROOT, files):
        raise ValueError('Unsafe source paths')
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    raw = encoded({'version': 1, 'source_head': head, 'files': files})
    (directory / 'source.json').write_bytes(raw)
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write('manifest_sha=' + digest(raw) + '\n')


def summarize_xml(path):
    tree = ET.parse(path)
    cases = list(tree.getroot().iter('testcase'))
    passed = []
    nonpassing = []
    for case in cases:
        name = case.get('name', '').split('[', 1)[0]
        if any(case.find(tag) is not None for tag in ['failure', 'error', 'skipped']):
            nonpassing.append(name if re.fullmatch(r'[A-Za-z0-9_]{1,160}', name) else 'collection_error')
            continue
        if not re.fullmatch(r'[A-Za-z0-9_]+', name):
            raise ValueError('Unexpected test identity')
        passed.append(name)
    return {'tests': len(cases), 'passed': len(passed),
            'nonpassing_cases': sorted(set(nonpassing)),
            'native_cases_passed': sorted(REQUIRED_NATIVE_CASES.intersection(passed))}


def run_native(directory, head, manifest_sha):
    manifest = read_manifest(directory, head, manifest_sha)
    system = os.uname()
    if (system.sysname != 'FreeBSD' or not system.release.startswith('15.1-')
            or system.machine != 'amd64' or os.geteuid() != 0 or not Path('/usr/bin/lockf').is_file()):
        raise ValueError('Native FreeBSD 15.1 root execution required')
    receipt = {'version': 1, 'source_head': head, 'manifest_sha': manifest_sha,
               'system': system.sysname, 'release': system.release, 'machine': system.machine,
               'uid': os.geteuid(), 'groups': {}, 'passed': False,
               'installed_opnsense_acceptance': False, 'frpc_installed_and_retested': False,
               'tools': dict({name: importlib.metadata.version(name) for name in ['pytest', 'Jinja2', 'jsonschema']},
                             python=sys.version.split()[0])}
    native_cases = set()
    for name, (_, paths) in GROUPS.items():
        xml = directory / (name + '.xml')
        try:
            result = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
                                     '--junitxml=' + str(xml), *paths], cwd=ROOT,
                                    capture_output=True, timeout=180)
            # Raw fixture diagnostics stay in the disposable guest and are not
            # copied into the allowlisted source/outcome artifacts or CI logs.
            summary = summarize_xml(xml)
            summary['exit_code'] = result.returncode
        except (OSError, subprocess.TimeoutExpired, ET.ParseError):
            summary = {'tests': 0, 'passed': 0, 'nonpassing_cases': ['test_runner_unavailable'],
                       'native_cases_passed': [], 'exit_code': 1}
        receipt['groups'][name] = summary
        native_cases.update(summary['native_cases_passed'])
    receipt['source_unchanged'] = source_matches(ROOT, manifest['files'])
    receipt['passed'] = (receipt['source_unchanged'] and native_cases == REQUIRED_NATIVE_CASES
                         and all(value['exit_code'] == 0 and value['tests'] == value['passed']
                                 and value['tests'] >= GROUPS[name][0]
                                 for name, value in receipt['groups'].items()))
    (directory / 'result.json').write_bytes(encoded(receipt))
    # Let the action copy the bounded receipt back even for failing tests. The
    # following independent host verification is the mandatory failing CI gate.
    print('Native contract outcomes recorded; host verification required')


def validate_receipt(value, head, manifest_sha):
    fields = {'version', 'source_head', 'manifest_sha', 'system', 'release', 'machine', 'uid',
              'groups', 'passed', 'source_unchanged', 'installed_opnsense_acceptance',
              'frpc_installed_and_retested', 'tools'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('Invalid native receipt shape')
    if (type(value['version']) is not int or value['version'] != 1
            or value['source_head'] != head or value['manifest_sha'] != manifest_sha
            or value['system'] != 'FreeBSD' or not isinstance(value['release'], str)
            or not re.fullmatch(r'15\.1-[A-Za-z0-9.-]{1,48}', value['release'])
            or value['machine'] != 'amd64' or type(value['uid']) is not int or value['uid'] != 0 or value['passed'] is not True
            or value['source_unchanged'] is not True or not isinstance(value['groups'], dict)
            or set(value['groups']) != set(GROUPS)
            or value['installed_opnsense_acceptance'] is not False or value['frpc_installed_and_retested'] is not False):
        raise ValueError('Native contract receipt failed')
    if (not isinstance(value['tools'], dict) or set(value['tools']) != {'pytest', 'Jinja2', 'jsonschema', 'python'}
            or any(not isinstance(version, str) or not re.fullmatch(r'[0-9][0-9A-Za-z.+_-]{0,63}', version)
                   for version in value['tools'].values())
            or not re.fullmatch(r'3\.13\.[0-9A-Za-z.]+', value['tools']['python'])):
        raise ValueError('Invalid native tool identities')
    native_cases = set()
    for name, summary in value['groups'].items():
        if (not isinstance(summary, dict) or set(summary) != {'tests', 'passed', 'exit_code', 'native_cases_passed', 'nonpassing_cases'}
                or type(summary['tests']) is not int or summary['tests'] < GROUPS[name][0]
                or type(summary['passed']) is not int or summary['tests'] != summary['passed']
                or type(summary['exit_code']) is not int or summary['exit_code'] != 0
                or not isinstance(summary['native_cases_passed'], list) or summary['nonpassing_cases'] != []):
            raise ValueError('A native contract did not pass')
        native_cases.update(summary['native_cases_passed'])
    if native_cases != REQUIRED_NATIVE_CASES:
        raise ValueError('Native lockf checks are missing')


def verify(directory, head, manifest_sha):
    read_manifest(directory, head, manifest_sha)
    raw = (directory / 'result.json').read_bytes()
    if len(raw) > 65536:
        raise ValueError('Oversized native receipt')
    validate_receipt(json.loads(raw), head, manifest_sha)
    subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--', *SCOPES], cwd=ROOT, check=True, capture_output=True)
    print('Exact-source FreeBSD 15.1 filesystem, lockf, PHP handoff and wire contracts passed; installed appliance acceptance remains separate')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'run', 'verify'])
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    head = os.environ['NETHUB_SOURCE_HEAD']
    if args.action == 'prepare':
        prepare(args.directory.resolve(), head)
    else:
        sha = os.environ['NETHUB_NATIVE_MANIFEST_SHA']
        (run_native if args.action == 'run' else verify)(args.directory.resolve(), head, sha)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Native source or contract verification failed; no acceptance recorded', file=sys.stderr)
        raise SystemExit(1)
