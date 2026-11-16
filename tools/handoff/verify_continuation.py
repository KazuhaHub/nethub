#!/usr/bin/env python3
"""Verify the first Ubuntu checkpoint without relabeling its failed native run."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

from verify import checked_path

ROOT = Path(__file__).resolve().parents[2]
HEAD = '870eb575cec13f4869e7848aac2cdc9b7c93307a'
CI = 43723295466
JOBS = {'Control plane checks', 'Go vulnerability checks', 'Deployment checks',
        'OPNsense plugin checks', 'weekend0 kit checks', 'workflow lint'}


def verify(root=ROOT):
    directory = root / 'docs/handoff/evidence/ubuntu-870eb57'
    index = json.loads((directory / 'index.json').read_text())
    assert index['version'] == 1 and index['source_head'] == HEAD
    assert index['full_project_complete'] is False and index['native_upgrade_cause_proven'] is False
    names = set()
    for item in index['files']:
        assert item['path'] not in names
        names.add(item['path'])
        path = checked_path(directory, item['path'])
        assert 0 < path.stat().st_size == item['bytes'] <= 16 * 1024**2
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256']
    runs = {run['kind']: run for run in index['runs']}
    assert len(runs) == 5 and set(runs) == {'CI', 'native', 'cold', 'preparation', 'filesystem'}
    for kind, run in runs.items():
        assert run['source_head'] == HEAD and run['attempt'] == 1
        assert run['conclusion'] == ('failure' if kind == 'native' else 'success')
        path = checked_path(directory, kind + '/run.json')
        metadata = json.loads(path.read_text())
        assert metadata['headSha'] == HEAD and metadata['status'] == 'completed'
        assert metadata['conclusion'] == run['conclusion']
        origin = json.loads(checked_path(directory, kind + '/run-origin.json').read_text())
        assert origin['head_sha'] == HEAD and origin['id'] == run['run_id']
        assert origin['run_attempt'] == run['attempt'] and origin['status'] == 'completed'
        assert origin['conclusion'] == run['conclusion']
        for artifact in run['artifacts']:
            if 'path' not in artifact:
                continue
            path = checked_path(directory, artifact['path'])
            assert path.stat().st_size == artifact['bytes']
            assert 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest() == artifact['digest']
            with zipfile.ZipFile(path) as archive:
                inventory = archive.namelist()
                assert inventory and len(inventory) == len(set(inventory))
                assert sum(i.file_size for i in archive.infolist()) <= 16 * 1024**2
                assert all(not Path(n).is_absolute() and '..' not in Path(n).parts and '\\' not in n for n in inventory)
    ci = json.loads((directory / 'CI/run.json').read_text())
    assert runs['CI']['run_id'] == CI and len(ci['jobs']) == 6
    assert {job['name'] for job in ci['jobs']} == JOBS
    assert all(job['status'] == 'completed' and job['conclusion'] == 'success' for job in ci['jobs'])

    def read(kind, name):
        with zipfile.ZipFile(directory / kind / 'original.zip') as archive:
            return json.loads(archive.read(name))

    native = read('native', 'deployment-result.json')
    assert native['source_head'] == HEAD and native['passed'] is False
    assert native['accepted_image_run'] == str(CI) and native['image_phase'] == 'verified'
    assert native['compose_setup']['phase'] == 'relay_heartbeat'
    assert native['owned_image_cleanup_confirmed'] is True
    assert native['formal_release'] is False and native['full_goal_complete'] is False
    with zipfile.ZipFile(directory / 'native/original.zip') as archive:
        assert archive.namelist() == ['deployment-result.json']
    cold = read('cold', 'result.json')
    assert cold['source_head'] == HEAD and cold['accepted_ci_run'] == CI and cold['passed'] is True
    assert cold['full_goal_complete'] is False
    assert cold['cleanup']['operation_cgroup_reaped'] is True
    assert cold['cleanup']['owned_private_VM_disks_keys_and_logs_removed'] is True
    assert cold['operation']['public_operator_durable_custody_renewal_clock_or_full_goal_accepted'] is False
    prep = read('preparation', 'result.json')
    assert prep['source_head'] == HEAD and prep['passed'] is True
    assert prep['formal_release'] is False and prep['full_goal_complete'] is False
    assert prep['installed']['frpc_compiler'] == 'go1.26.11' and prep['installed']['frp_version'] == '0.71.1'
    source = subprocess.check_output(['git', '-C', str(root), '-c', 'core.autocrlf=false', 'archive', '--format=tar', HEAD])
    assert hashlib.sha256(source).hexdigest() == prep['source_archive_sha256']
    for kind, value in [('cold', cold), ('preparation', prep['page'])]:
        with zipfile.ZipFile(directory / kind / 'original.zip') as archive:
            for name, digest in value['screenshots'].items():
                assert hashlib.sha256(archive.read(name)).hexdigest() == digest
    manifest = read('filesystem', 'source.json')
    receipt = read('filesystem', 'result.json')
    assert manifest['source_head'] == receipt['source_head'] == HEAD and len(manifest['files']) == 256
    assert receipt['passed'] is True and receipt['source_unchanged'] is True
    assert receipt['installed_opnsense_acceptance'] is False and receipt['frpc_installed_and_retested'] is False
    assert {k: v['passed'] for k, v in receipt['groups'].items()} == {'enrollment': 14, 'service': 57, 'wire': 177}
    for name, digest in manifest['files'].items():
        raw = subprocess.check_output(['git', '-C', str(root), 'show', HEAD + ':' + name])
        assert hashlib.sha256(raw).hexdigest() == digest
    print(f"Verified {len(names)} closed Ubuntu evidence files and five exact-source runs; native preparation failure remains failed.")
    print('Verified 256 original source blobs, preparation archive and native/cold screenshot hashes. No upgrade or release acceptance.')


def verify_preflight(root=ROOT):
    directory = root / 'docs/handoff/evidence/ubuntu-native-preflight'
    index = json.loads((directory / 'index.json').read_text())
    assert index['version'] == 1 and index['full_project_complete'] is False
    assert index['native_upgrade_cause_proven'] is False
    names = set()
    for item in index['files']:
        assert item['path'] not in names
        names.add(item['path'])
        raw = checked_path(directory, item['path']).read_bytes()
        assert 0 < len(raw) == item['bytes'] <= 16 * 1024**2
        assert hashlib.sha256(raw).hexdigest() == item['sha256']
    expected = {
        '38bec4dd17f7d63f330f958f163f5c61e43e8a64': (43727962907, 43727962910, 43727962999,
            'private guest input transfer failed: guest_ssh_connect_timeout'),
        'b2bfb5070832fcc7deae202e197c43f22bcfb77f': (43730193170, 43730193174, 43730193155,
            'native package snapshot failed: fixture_native_package_boundary'),
    }
    assert {c['source_head'] for c in index['checkpoints']} == set(expected)
    assert len(index['checkpoints']) == 2
    for checkpoint in index['checkpoints']:
        head = checkpoint['source_head']
        ci, native, cold, failure = expected[head]
        runs = {r['kind']: r for r in checkpoint['runs']}
        assert len(checkpoint['runs']) == 3 and set(runs) == {'CI', 'native', 'cold'}
        for kind, run_id in [('CI', ci), ('native', native), ('cold', cold)]:
            run = runs[kind]
            assert run['run_id'] == run_id and run['attempt'] == 1
            path = checked_path(directory, run['directory'] + '/run.json').parent
            metadata = json.loads((path / 'run.json').read_text())
            origin = json.loads((path / 'run-origin.json').read_text())
            conclusion = 'failure' if kind == 'native' else 'success'
            assert run['conclusion'] == metadata['conclusion'] == origin['conclusion'] == conclusion
            assert metadata['status'] == origin['status'] == 'completed'
            assert metadata['headSha'] == origin['head_sha'] == head
            assert origin['id'] == run_id and origin['run_attempt'] == 1
            if kind == 'CI':
                assert len(metadata['jobs']) == 6 and {j['name'] for j in metadata['jobs']} == JOBS
                assert all(j['status'] == 'completed' and j['conclusion'] == 'success' for j in metadata['jobs'])
                continue
            raw = (path / 'original.zip').read_bytes()
            assert len(raw) == run['artifact']['bytes']
            assert 'sha256:' + hashlib.sha256(raw).hexdigest() == run['artifact']['digest']
            with zipfile.ZipFile(path / 'original.zip') as archive:
                inventory = archive.namelist()
                assert inventory and len(inventory) == len(set(inventory))
                assert sum(i.file_size for i in archive.infolist()) <= 16 * 1024**2
                assert all(not Path(n).is_absolute() and '..' not in Path(n).parts and '\\' not in n for n in inventory)
                if kind == 'native':
                    value = json.loads(archive.read('native/result.json'))
                    deployment = json.loads(archive.read('deployment-result.json'))
                    wan = json.loads(archive.read('native/installed-wan-recovery.json'))
                    assert value['source_head'] == deployment['source_head'] == head
                    assert value['passed'] is False and value['failure'] == failure
                    assert deployment['passed'] is False and deployment['accepted_image_run'] == str(ci)
                    assert deployment['owned_image_cleanup_confirmed'] is True
                    assert wan['passed'] is True and wan['full_W5_acceptance'] is False
                    if run_id == 43727962910:
                        migration = json.loads(archive.read('native/installed-package-migration.json'))
                        assert migration['passed'] is False and migration['phase'] == 'baseline'
                        assert migration['steps'] == migration['outages'] == migration['invariant_failures'] == []
                    else:
                        assert 'native/installed-package-migration.json' not in inventory
                else:
                    value = json.loads(archive.read('result.json'))
                    assert value['source_head'] == head and value['accepted_ci_run'] == ci
                    assert value['passed'] is True and value['full_goal_complete'] is False
                    assert value['cleanup']['operation_cgroup_reaped'] is True
                    assert value['cleanup']['owned_private_VM_disks_keys_and_logs_removed'] is True
                    assert value['operation']['public_operator_durable_custody_renewal_clock_or_full_goal_accepted'] is False
                    for name, digest in value['screenshots'].items():
                        assert hashlib.sha256(archive.read(name)).hexdigest() == digest
    print(f'Verified {len(names)} later closed files and six source-separated runs; both native preflight failures remain failed.')


def verify_local_load(root=ROOT):
    directory = root / 'docs/handoff/evidence/ubuntu-52e3362-local'
    index = json.loads((directory / 'index.json').read_text())
    head = '52e3362625b1de18399bb7ff6a68aeaca516aabb'
    assert index['source_head'] == head and index['full_project_complete'] is False
    assert index['kind'] == 'local-actual-SQL' and len(index['files']) == 1
    item = index['files'][0]
    assert item['path'] == 'snapshot-load.json'
    raw = checked_path(directory, item['path']).read_bytes()
    assert len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256']
    value = json.loads(raw)
    assert value['source_head'] == head and value['passed'] is True and value['exit_code'] == 0
    assert value['revocation_load_enabled'] is True and value['ordinary_top_level_passed'] == 8
    assert all(value[k] is True for k in ('explicit_load_passed', 'tenant_overflow_denial_retained',
                                         'owned_container_cleanup_confirmed'))
    assert value['public_or_native_acceptance'] is value['online_fleet_capacity_accepted'] is False
    assert value['compiler'] == 'go1.26.11'
    assert value['compiled_cli_build'] == {'CGO_ENABLED': '0', 'GOARCH': 'amd64', 'GOOS': 'linux',
        'vcs.revision': head, 'vcs.modified': 'false'}
    assert len(value['metrics']) == 4
    for record, size in zip(value['metrics'], (1000, 10000, 100000, 100000)):
        assert record['revoked_rows'] == record['rotation_floors'] == size
        assert record['refresh_succeeded'] is True and record['live_client_capacity_accepted'] is False
        assert record['refresh_budget_ms'] == 1000 and 0 < record['refresh_us'] <= 1000000
        assert record['memory_predicate_triplets'] == 10000 and 1 <= record['tenants'] <= 1024
    assert value['metrics'][-1]['tenants'] == 1024
    for name, digest in value['source_files'].items():
        source = subprocess.check_output(['git', '-C', str(root), 'show', head + ':' + name])
        assert hashlib.sha256(source).hexdigest() == digest
    print('Verified local SQL/load record and exact source hashes; no online-fleet, native or public acceptance.')


def verify_runtime_checkpoint(root, head, expected, source_count, failure_stage):
    directory = root / ('docs/handoff/evidence/ubuntu-' + head[:7])
    index = json.loads((directory / 'index.json').read_text())
    assert index['source_head'] == head and index['version'] == 1
    assert index['full_project_complete'] is index['native_upgrade_cause_proven'] is False
    names = set()
    for item in index['files']:
        assert item['path'] not in names
        names.add(item['path'])
        raw = checked_path(directory, item['path']).read_bytes()
        assert 0 < len(raw) == item['bytes'] <= 16 * 1024**2
        assert hashlib.sha256(raw).hexdigest() == item['sha256']
    runs = {r['kind']: r for r in index['runs']}
    assert len(index['runs']) == len(expected) and set(runs) == set(expected)
    for kind, identifier in expected.items():
        run = runs[kind]
        assert run['run_id'] == identifier and run['attempt'] == 1 and run['source_head'] == head
        metadata = json.loads((directory / kind / 'run.json').read_text())
        origin = json.loads((directory / kind / 'run-origin.json').read_text())
        conclusion = 'failure' if kind == 'native' else 'success'
        assert run['conclusion'] == metadata['conclusion'] == origin['conclusion'] == conclusion
        assert metadata['headSha'] == origin['head_sha'] == head and origin['id'] == identifier
        assert origin['run_attempt'] == 1 and metadata['status'] == origin['status'] == 'completed'
        if kind == 'CI':
            assert len(metadata['jobs']) == 6 and {j['name'] for j in metadata['jobs']} == JOBS
            assert all(j['status'] == 'completed' and j['conclusion'] == 'success' for j in metadata['jobs'])
        else:
            assert len(run['artifacts']) == 1
            artifact = run['artifacts'][0]
            raw = checked_path(directory, artifact['path']).read_bytes()
            assert len(raw) == artifact['bytes'] and 'sha256:' + hashlib.sha256(raw).hexdigest() == artifact['digest']

    def read(kind, name):
        with zipfile.ZipFile(directory / kind / 'original.zip') as archive:
            inventory = archive.namelist()
            assert len(inventory) == len(set(inventory))
            assert sum(i.file_size for i in archive.infolist()) <= 16 * 1024**2
            assert all(not Path(n).is_absolute() and '..' not in Path(n).parts and '\\' not in n for n in inventory)
            return json.loads(archive.read(name))

    deployment = read('native', 'deployment-result.json')
    assert deployment['source_head'] == head
    assert deployment['accepted_image_run'] == str(expected['CI']) and deployment['image_phase'] == 'verified'
    assert deployment['passed'] is False and deployment['owned_image_cleanup_confirmed'] is True
    if failure_stage == 'post_WAN':
        native = read('native', 'native/result.json')
        assert native['source_head'] == head and native['passed'] is False
        assert native['failure'] == 'Guest console after WAN probe failed at tls: http_failure'
        assert read('native', 'native/installed-wan-recovery.json')['passed'] is True
        assert read('native', 'native/guest-console-after-wan-probe.json')['passed'] is False
    elif failure_stage in ('authz_log', 'plain_service_failure'):
        assert deployment['compose_setup']['phase'] == 'relay_heartbeat'
        assert deployment['failure'] == 'Owned native deployment failed at relay_heartbeat'
        if failure_stage == 'authz_log':
            assert deployment['compose_setup']['hints'] == []
            assert {'source': 'relay_deployment', 'line': 60} in deployment['compose_setup']['locations']
        else:
            assert deployment['compose_setup']['hints'] == [
                'relay_hook_log_invalid_record', 'relay_hook_log_plain_prefix', 'relay_hook_log_service_failure']
            assert {'source': 'relay_log', 'line': 34} in deployment['compose_setup']['locations']
        with zipfile.ZipFile(directory / 'native/original.zip') as archive:
            assert archive.namelist() == ['deployment-result.json']
    elif failure_stage == 'fleet_control':
        assert deployment['compose_setup']['phase'] == 'relay_fleet'
        assert deployment['failure'] == 'Owned native deployment failed at relay_fleet'
        assert deployment['compose_setup']['hints'] == []
        assert {'source': 'relay_fleet', 'line': 133} in deployment['compose_setup']['locations']
        with zipfile.ZipFile(directory / 'native/original.zip') as archive:
            assert archive.namelist() == ['deployment-result.json']
    else:
        raise ValueError('Unknown recorded failure stage')
    with zipfile.ZipFile(directory / 'native/original.zip') as archive:
        assert 'native/installed-package-migration.json' not in archive.namelist()
    cold = read('cold', 'result.json')
    assert cold['source_head'] == head and cold['accepted_ci_run'] == expected['CI'] and cold['passed'] is True
    assert cold['full_goal_complete'] is False and cold['cleanup']['operation_cgroup_reaped'] is True
    assert cold['cleanup']['owned_private_VM_disks_keys_and_logs_removed'] is True
    assert cold['operation']['public_operator_durable_custody_renewal_clock_or_full_goal_accepted'] is False
    prep = read('preparation', 'result.json')
    assert prep['source_head'] == head and prep['passed'] is True and prep['formal_release'] is False
    assert prep['installed']['frpc_compiler'] == 'go1.26.11' and prep['installed']['frp_version'] == '0.71.1'
    source = subprocess.check_output(['git', '-C', str(root), '-c', 'core.autocrlf=false', 'archive', '--format=tar', head])
    assert hashlib.sha256(source).hexdigest() == prep['source_archive_sha256']
    for kind, value in [('cold', cold), ('preparation', prep['page'])]:
        with zipfile.ZipFile(directory / kind / 'original.zip') as archive:
            for name, digest in value['screenshots'].items():
                assert hashlib.sha256(archive.read(name)).hexdigest() == digest
    manifest, receipt = read('filesystem', 'source.json'), read('filesystem', 'result.json')
    assert manifest['source_head'] == receipt['source_head'] == head and len(manifest['files']) == source_count
    contract_source = subprocess.check_output(['git', '-C', str(root), 'show', head + ':agents/opnsense/native_contracts.py'])
    settings = {}
    for node in ast.parse(contract_source).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in ('GROUPS', 'REQUIRED_NATIVE_CASES'):
                settings[node.targets[0].id] = ast.literal_eval(node.value)
    assert set(settings) == {'GROUPS', 'REQUIRED_NATIVE_CASES'}
    with zipfile.ZipFile(directory / 'filesystem/original.zip') as archive:
        assert receipt['manifest_sha'] == hashlib.sha256(archive.read('source.json')).hexdigest()
    assert receipt['passed'] is receipt['source_unchanged'] is True
    assert receipt['installed_opnsense_acceptance'] is receipt['frpc_installed_and_retested'] is False
    assert set(receipt['groups']) == set(settings['GROUPS'])
    native_cases = set()
    for name, group in receipt['groups'].items():
        assert group['tests'] == group['passed'] >= settings['GROUPS'][name][0]
        assert group['exit_code'] == 0 and group['nonpassing_cases'] == []
        native_cases.update(group['native_cases_passed'])
    assert native_cases == settings['REQUIRED_NATIVE_CASES']
    assert sum(g['passed'] for g in receipt['groups'].values()) == 252
    for name, digest in manifest['files'].items():
        assert hashlib.sha256(subprocess.check_output(['git', '-C', str(root), 'show', head + ':' + name])).hexdigest() == digest
    images = list((directory / 'CI').glob('*.png'))
    old = root / 'docs/handoff/evidence/ubuntu-870eb57/CI'
    assert len(images) == 13 and {p.name for p in images} == {p.name for p in old.glob('*.png')}
    assert sum(p.read_bytes() == (old / p.name).read_bytes() for p in images) == 6
    assert index['required_image_review'] == {'images': 13, 'identical_to_reviewed_870eb57': 6, 'changed_views_reviewed': 7}
    print(f'Verified {len(names)} checkpoint files for {head[:7]}, five exact-source runs and {source_count} source blobs; {failure_stage} failure remains failed.')


def verify_local_framing(root=ROOT):
    directory = root / 'docs/handoff/evidence/local-relay-log-framing'
    index = json.loads((directory / 'index.json').read_text())
    assert index['version'] == 1 and index['native_failure_cause_proven'] is False
    assert index['source_head'] == '2523ab981f953e0a4d5dce994fbdff593d09d8fe'
    assert hashlib.sha256((root / 'tools/handoff/reproduce_relay_log.py').read_bytes()).hexdigest() == index['reproducer_sha256']
    assert len(index['files']) == 1
    item = index['files'][0]
    raw = checked_path(directory, item['path']).read_bytes()
    assert item['path'] == 'result.json' and len(raw) == item['bytes']
    assert hashlib.sha256(raw).hexdigest() == item['sha256']
    value = json.loads(raw)
    assert value['helper_source_commit'] == index['source_head']
    source = subprocess.check_output(['git', '-C', str(root), 'show', index['source_head'] + ':server/tests/relay_log.py'])
    assert hashlib.sha256(source).hexdigest() == value['helper_sha256']
    assert value['framing_reproduction_passed'] is value['owned_container_cleanup_confirmed'] is True
    assert value['all_padding_preserved'] is value['completed_json_valid'] is True
    assert value['first_json_valid'] is value['first_ends_newline'] is value['product_native_or_public_accepted'] is False
    assert value['first_bytes'] == 16384 and value['completed_bytes'] == 20043
    assert value['reader_calls'] == 2 and value['parsed_events'] == 1 and value['log_driver'] == 'json-file'
    print('Verified local Docker framing reproduction; native failure attribution remains unproven.')


if __name__ == '__main__':
    verify()
    verify_preflight()
    verify_local_load()
    verify_runtime_checkpoint(ROOT, '52e3362625b1de18399bb7ff6a68aeaca516aabb',
        {'CI': 43760255115, 'native': 43760255139, 'cold': 43760255138,
         'preparation': 43760255136, 'filesystem': 43760255102}, 257, 'post_WAN')
    verify_runtime_checkpoint(ROOT, '359bf94eab8c3339671fb1b0af1a6c4133f26ad1',
        {'CI': 43766613173, 'native': 43766613555, 'cold': 43766613544,
         'preparation': 43766613091, 'filesystem': 43766613099}, 258, 'authz_log')
    verify_runtime_checkpoint(ROOT, '2523ab981f953e0a4d5dce994fbdff593d09d8fe',
        {'CI': 43772146655, 'native': 43772146507, 'cold': 43772146549,
         'preparation': 43772146624, 'filesystem': 43772146565}, 258, 'plain_service_failure')
    verify_local_framing()
    verify_runtime_checkpoint(ROOT, 'd33302f5420f6d90cc04b7e5142bc9660569d987',
        {'CI': 43776402103, 'native': 43776401967, 'cold': 43776401975,
         'preparation': 43776401980, 'filesystem': 43776401969}, 258, 'fleet_control')
