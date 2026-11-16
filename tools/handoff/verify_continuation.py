#!/usr/bin/env python3
"""Verify source-bound Ubuntu checkpoints while retaining every earlier failure."""
import ast
import hashlib
import json
import re
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
        conclusion = 'failure' if kind == 'native' and failure_stage != 'native_pass' else 'success'
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
    assert deployment['passed'] is (failure_stage == 'native_pass')
    assert deployment['owned_image_cleanup_confirmed'] is True
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
    elif failure_stage == 'package_route_boundary':
        native = read('native', 'native/result.json')
        assert native['source_head'] == head and native['passed'] is False
        assert native['failure'] == 'native package snapshot failed: fixture_native_package_boundary_route'
        assert native['read_only_inspection_recoveries'] == []
        assert native['guest_diagnostic']['guest_exit_status_after_cleanup'] == 0
        assert deployment['compose_setup']['phase'] == 'native_guest'
        assert deployment['compose_tail'] is None
        assert read('native', 'native/installed-wan-recovery.json')['passed'] is True
        assert read('native', 'native/guest-console-after-wan-probe.json')['passed'] is True
        with zipfile.ZipFile(directory / 'native/original.zip') as archive:
            page = read('native', 'native/installed-enroll-page.json')
            assert page['passed'] is page['actual_native_write_API'] is True
            for name, digest in page['screenshots'].items():
                assert hashlib.sha256(archive.read('native/' + name)).hexdigest() == digest
    elif failure_stage == 'native_pass':
        verify_installed_success(root, directory, head, index, deployment, read)
    else:
        raise ValueError('Unknown recorded failure stage')
    with zipfile.ZipFile(directory / 'native/original.zip') as archive:
        assert ('native/installed-package-migration.json' in archive.namelist()) is (failure_stage == 'native_pass')
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
    outcome = 'scoped installed success; earlier failures remain failed' if failure_stage == 'native_pass' else failure_stage + ' failure remains failed'
    print(f'Verified {len(names)} checkpoint files for {head[:7]}, five exact-source runs and {source_count} source blobs; {outcome}.')


def verify_installed_success(root, directory, head, index, deployment, read):
    """Check this completed run without changing the older failure branches."""
    assert index['native_upgrade_current_source_passed'] is True
    native = read('native', 'native/result.json')
    rotation = read('native', 'native/installed-rotation.json')
    package = read('native', 'native/installed-package-migration.json')
    assert native['source_head'] == package['current_source'] == head
    assert native['passed'] is rotation['passed'] is package['passed'] is True
    assert native['phase'] == package['phase'] == 'completed'
    assert native['full_rotation_acceptance'] is native['full_goal_complete'] is False
    assert native['formal_release'] is native['public_network_acceptance'] is False
    assert native['guest_diagnostic']['guest_exit_status_after_cleanup'] == 0
    assert native['source_archive_sha256'] == read('preparation', 'result.json')['source_archive_sha256']
    assert deployment['installed_rotation'] == native['installed_rotation'] == rotation
    assert rotation['installed_package_migration'] == package

    # Execute only the selected source's pure schema validator and its constants.
    # No guest, package operation, network call or inspection recovery is imported.
    probe_source = subprocess.check_output(['git', '-C', str(root), 'show', head + ':agents/opnsense/acceptance/package_probe.py'])
    hashes = [node for node in ast.parse(probe_source).body if isinstance(node, ast.Assign)
              and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'HASHES']
    assert len(hashes) == 1
    context = {'re': re, 'HASHES': ast.literal_eval(hashes[0].value)}
    source = subprocess.check_output(['git', '-C', str(root), 'show', head + ':agents/opnsense/acceptance/package_migration.py'])
    constants = {'BASELINE', 'VERSIONS', 'PROFILES', 'PHASES', 'FLAGS', 'LIMITS', 'PHASE_VERSIONS',
                 'OUTAGE_PHASES', 'OUTAGE_FLAGS', 'INVARIANTS'}
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.Assign) and len(node.targets) == 1
             and isinstance(node.targets[0], ast.Name) and node.targets[0].id in constants
             or isinstance(node, ast.FunctionDef) and node.name in ('validate', 'validate_packages')]
    assert len(nodes) == len(constants) + 2
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<recorded-package-schema>', 'exec'), context)
    context['validate'](package)
    context['validate_packages'](native['package_baseline'])
    assert package['invariant_failures'] == [] and package['package_sha256'] == native['package_baseline']['package_sha256']
    assert [row['phase'] for row in package['steps']] == list(context['PHASES'][:-1])
    assert all(package[key] is True for key in context['FLAGS'])
    assert all(package[key] is False for key in context['LIMITS'])
    baseline = native['package_baseline']
    raw = subprocess.check_output(['git', '-C', str(root), '-c', 'core.autocrlf=false', 'archive', '--format=tar', baseline['baseline_source']])
    assert hashlib.sha256(raw).hexdigest() == baseline['baseline_source_archive_sha256']

    for name, key in [('installed-shared-token.json', 'shared_token_incident_native_recovery'),
                      ('installed-host-restore.json', 'clean_host_restoration'),
                      ('installed-trust-publication.json', 'installed_trust_publication_conflict_recovery'),
                      ('installed-committed-trust-replay.json', 'installed_committed_trust_replay'),
                      ('installed-wan-recovery.json', 'installed_wan_recovery'),
                      ('installed-console-revoke.json', 'installed_console_revoke_deadline')]:
        value = read('native', 'native/' + name)
        assert value == rotation[key] and value['passed'] is True
    tail = read('native', 'native/compose-tail.json')
    assert tail == deployment['compose_tail'] == {'version': 1, 'phase': 'completed', 'passed': True}
    assert rotation['removed_fixture_revoked_model_cleared_service_stopped_route_closed'] is True
    assert rotation['independent_device_preserved_after_fixture_removal'] is True
    revoke = rotation['installed_console_revoke_deadline']
    assert revoke['deadline_ms'] == 5000 and 0 < revoke['native_proxy_offline_ms'] <= 5000
    assert revoke['clock_start'] == 'before normal console confirmation click'
    assert revoke['no_reconnect_observation_ms'] >= 30000
    assert all(revoke[key] is True for key in ('normal_browser_CSRF_protected_revoke',
        'fresh_verified_native_route_refused', 'independent_original_control_and_verified_TLS_retained',
        'native_identity_and_grants_retained', 'valid_source_grant_retained_during_TLS_refusal'))
    assert revoke['full_W5_acceptance'] is revoke['public_network_acceptance'] is False
    assert rotation['full_goal_complete'] is rotation['public_network_or_formal_release_acceptance'] is False
    receipt = json.loads((directory / 'native/scoped-verification.json').read_text())
    native_run = next(row['run_id'] for row in index['runs'] if row['kind'] == 'native')
    assert receipt['source_head'] == head and receipt['run'] == native_run
    assert receipt['native_upgrade_original_cause_proven'] is receipt['full_W5_W7_or_release_accepted'] is False
    images = receipt['images']
    assert len(images) == 14 and len({value['name'] for value in images}) == 14
    assert len({value['sha256'] for value in images}) == 9
    with zipfile.ZipFile(directory / 'native/original.zip') as archive:
        for item in images:
            assert item['archive_member'] == 'native/' + item['name']
            assert hashlib.sha256(archive.read(item['archive_member'])).hexdigest() == item['sha256']
            if not item['view_reviewed']:
                reference = [v for v in images if v['name'] == item['identical_to_reviewed_image']]
                assert len(reference) == 1 and reference[0]['view_reviewed'] is True
                assert reference[0]['sha256'] == item['sha256']


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


def verify_external_tcp_report(root=ROOT):
    directory = root / 'docs/handoff/evidence/external-tcp-report'
    index = json.loads((directory / 'index.json').read_text())
    head = '898c3e0e474aaf03c294c78c37d9e6c96630b6fb'
    parent = '16708e35443fbbe93344bd897f8d5ab3ef6749d0'
    assert index['version'] == 1 and index['source_head'] == head and index['parent_source'] == parent
    assert index['public_positive_sample_accepted'] is index['full_project_complete'] is False
    expected = {'parent-refusal.json', 'report-shape.json', 'fixed-refusal.json',
                'local-checks.json', 'clean-build.json', 'NAT-fixture-ready.json',
                'python-diagnostic-refusal.json', 'retained-report-final.json'}
    assert len(index['files']) == len(expected) and {v['path'] for v in index['files']} == expected
    values = {}
    for item in index['files']:
        raw = checked_path(directory, item['path']).read_bytes()
        assert 0 < len(raw) == item['bytes'] <= 16384
        assert hashlib.sha256(raw).hexdigest() == item['sha256']
        values[item['path']] = json.loads(raw)
    before, after = values['parent-refusal.json'], values['fixed-refusal.json']
    assert before['source_head'] == parent and after['source_head'] == head
    for value in (before, after):
        assert value['target_is_own_host'] is value['no_partial_success'] is True
        assert value['host_ports_listening'] is value['public_forward_mutated'] is False
        assert value['provider_submission_attempts'] == 1 and value['exit_status'] == 1
        assert 0 < value['elapsed_ms'] <= 55000
        assert value['stdout_sha256'] == hashlib.sha256(b'').hexdigest()
        assert value['public_positive_sample_accepted'] is value['full_W7_or_release_accepted'] is False
    assert before['verified_closed_observer_refusal'] is False
    assert after['verified_closed_observer_refusal'] is True
    shape = values['report-shape.json']
    assert shape['scheduled_nodes'] == shape['observed_nodes'] == 3
    for key in ('observer_identities_match', 'command_matches_tcp',
                'report_host_is_exact_owned_IP', 'report_port_is_exact_requested_decimal'):
        assert shape[key] is True
    assert shape['host_matches_exact_target'] is shape['public_positive_or_closed_sample_accepted'] is False
    assert shape['report_port_type'] == 'str' and abs(shape['creation_clock_delta_seconds']) <= 10
    local, build = values['local-checks.json'], values['clean-build.json']
    assert local['source_head'] == build['source_head'] == head
    assert local['parent_source'] == parent
    assert local['parent_parser_genuine_shape_reproduction_failed'] is local['fixed_local_tests_passed'] is True
    assert local['top_level_Go_tests_passed'] == 41 and local['new_target_denial_subcases'] == 5
    assert local['Go_version'] == build['go_version'] == '1.26.11'
    assert local['network'] == build['network'] == 'none' and local['CPU_limit'] == build['CPU_limit'] == 2
    assert local['gofmt_vet_build_passed'] is build['clean_build'] is True
    assert local['native_or_full_public_acceptance'] is build['formal_release'] is False
    assert after['binary_sha256'] == build['binary_sha256']
    assert len(local['feature_blobs']) == 3 and len(local['native_files_unchanged_from_ea173c6']) == 10
    for path, digest in local['feature_blobs'].items():
        assert hashlib.sha256(subprocess.check_output(['git', '-C', str(root), 'show', head + ':' + path])).hexdigest() == digest
    for row in local['native_files_unchanged_from_ea173c6']:
        raw = subprocess.check_output(['git', '-C', str(root), 'show', head + ':' + row['path']])
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
        assert raw == subprocess.check_output(['git', '-C', str(root), 'show',
            'ea173c660a38bd6c61f37f013e58761da4f337ae:' + row['path']])
    final = values['retained-report-final.json']
    for key in ('same_retained_request_identity', 'target_is_own_host',
                'exact_host_and_port_matched', 'original_creation_timestamp_retained', 'all_three_failed'):
        assert final[key] is True
    assert final['new_submission_performed'] is final['public_positive_or_full_acceptance'] is False
    assert final['scheduled_and_reported_observers'] == final['failed_observers_without_success_time'] == 3
    assert final['pending_observers'] == 0
    refusal = values['python-diagnostic-refusal.json']
    assert refusal['HTTP_status'] == 403 and refusal['provider_result_received'] is refusal['public_sample_accepted'] is False
    fixture = values['NAT-fixture-ready.json']
    assert fixture['vCPU'] == 1 and fixture['memory_MiB'] == 1024
    for key in ('pinned_Canonical_image_verified', 'uploaded_image_and_seed_sha256_verified',
                'pinned_SSH_host_key_verified', 'powered_off_waiting_owner'):
        assert fixture[key] is True
    assert fixture['private_TCP_ports_verified'] == [14443, 17000, 18443]
    assert fixture['public_exposure_authorized'] is fixture['public_forward_mutated'] is False
    print('Verified strict TCP report correction, retained mismatch/403 refusals and owned-port negative sample; positive/public-release scope remains open.')


def verify_local_opnsense_baseline():
    value = json.loads((ROOT / 'docs/handoff/evidence/local-opnsense-baseline/result.json').read_text())
    assert value['version'] == 1
    assert value['verification_source_head'] == 'f98e8ceba3b85c485a3f63b76054430eb59be22e'
    assert value['verification_source_path'] == 'agents/opnsense/acceptance/guest.py'
    source = subprocess.check_output(['git', '-C', str(ROOT), 'show',
        value['verification_source_head'] + ':' + value['verification_source_path']])
    assert hashlib.sha256(source).hexdigest() == value['verification_source_sha256']
    image, baseline = value['image'], value['baseline']
    assert image['signature_verified'] is True
    assert image['compressed_sha256'] == '28d5e2f37e40d87468a924e3006ef10e2ddc6de485b85333d9e3958c84d0cb9d'
    assert image['raw_sha256'] == 'c376b498338e9e0ddd785ac447f933e940f7d556810779475eecef30d37fcb98'
    assert re.fullmatch('[a-f0-9]{64}', image['converted_disk_sha256'])
    assert baseline['guest_system'] == 'FreeBSD' and baseline['guest_version'] == 'OPNsense 26.7 (amd64)'
    assert baseline['memory_MiB'] == 3072 and baseline['vCPU'] == 2
    for key in ('official_image_signature_verified', 'disk_transfer_hash_verified',
                'independent_serial_console_boot_verified', 'both_network_links_disconnected', 'gracefully_powered_off'):
        assert baseline[key] is True
    for key in ('public_ports_exposed', 'host_network_definition_changed',
                'installed_NetHub_or_native_migration_or_release_accepted'):
        assert baseline[key] is False
    assert value['earlier_readback_wrapper_refusals_retained'] == 3 and value['host_start_requests'] == 1
    for key in ('guest_pkg_install_or_SQL_replay', 'host_sudo_or_firewall_or_default_network_change',
                'hosted_acceptance_guard_changed_or_forged', 'public_mobile_independent_operator_or_release_accepted'):
        assert value[key] is False
    auth = json.loads((ROOT / 'docs/handoff/evidence/local-opnsense-baseline/private-auth-result.json').read_text())
    assert auth['version'] == 1
    assert auth['source']['repository'] == 'opnsense/core' and auth['source']['tag'] == '26.7'
    assert auth['source']['path'] == 'src/opnsense/scripts/shell/password.php'
    assert re.fullmatch('[a-f0-9]{40}', auth['source']['commit'])
    assert re.fullmatch('[a-f0-9]{64}', auth['source']['sha256'])
    result = auth['result']
    assert result['password_change_requests'] == 1
    for key in ('stock_native_password_source_verified', 'unrelated_configuration_preserved',
                'factory_password_refused', 'fresh_private_password_login_verified',
                'password_absent_from_serial_output', 'private_credential_outside_repository',
                'both_network_links_disconnected', 'native_WAN_DHCP_and_interface_roles_verified',
                'gracefully_powered_off'):
        assert result[key] is True
    assert result['host_firewall_network_or_public_forward_changed'] is False
    assert result['NetHub_or_native_migration_or_release_accepted'] is False
    nat = json.loads((ROOT / 'docs/handoff/evidence/local-opnsense-baseline/nat-metadata-result.json').read_text())
    assert nat['version'] == 1
    assert (nat['observed_upgrade_candidate_count'], nat['observed_new_packages'], nat['observed_upgrades']) == (95, 3, 92)
    assert nat['original_nonzero_preview_retained'] is True
    assert nat['metadata_operation_replayed'] is False
    assert nat['guest_shutdown_delivery_observation_refusal_retained'] is True
    result = nat['result']
    assert result['metadata_refresh_requests'] == 1 and result['package_upgrade_requests'] == 0
    assert result['upgrade_dry_run_exit_code'] == 1 and result['upgrade_plan_accepted'] is False
    for key in ('WAN_only_existing_NAT_verified', 'LAN_link_remained_down',
                'official_HTTPS_and_fingerprint_repository_verified', 'outbound_TLS_verified',
                'metadata_refresh_completed', 'installed_package_inventory_unchanged',
                'private_password_absent_from_serial_output', 'host_default_network_definition_unchanged',
                'gracefully_powered_off', 'shutdown_delivery_observed'):
        assert result[key] is True
    assert result['public_forward_or_host_firewall_changed'] is False
    assert result['NetHub_native_public_or_release_accepted'] is False
    print('Verified local appliance preparation and retained nonzero upgrade preview; no installed NetHub, native migration or release acceptance.')


def verify_semantic_review(root=ROOT):
    value = json.loads((root / 'docs/handoff/evidence/semantic-review-109aab5.json').read_text())
    assert value['source_head'] == '109aab5063dc056f794ef2c98f8ba2d6ca0717a9'
    assert value['all_documents_reviewed'] is value['actual_public_renewal_accepted'] is False
    assert len(value['files']) == len({row['path'] for row in value['files']}) == 138
    for row in value['files']:
        assert row['path'].endswith('.md') and not Path(row['path']).is_absolute() and '..' not in Path(row['path']).parts
        raw = subprocess.check_output(['git', '-C', str(root), 'show', value['source_head'] + ':' + row['path']])
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
    print('Verified 138 source-bound partial document reviews; exhaustive review, public renewal and independent deployment remain open.')


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
    verify_runtime_checkpoint(ROOT, 'ea173c660a38bd6c61f37f013e58761da4f337ae',
        {'CI': 43783251653, 'native': 43783251698, 'cold': 43783251668,
         'preparation': 43783251640, 'filesystem': 43783251552}, 258, 'native_pass')

    verify_external_tcp_report()

    verify_runtime_checkpoint(ROOT, '16708e35443fbbe93344bd897f8d5ab3ef6749d0',
        {'CI': 43791395178, 'native': 43799096360, 'cold': 43799098898,
         'preparation': 43791538230, 'filesystem': 43791394959}, 258, 'native_pass')

    verify_runtime_checkpoint(ROOT, '109aab5063dc056f794ef2c98f8ba2d6ca0717a9',
        {'CI': 43801873400, 'native': 43801873221, 'cold': 43805004536,
         'preparation': 43802001135, 'filesystem': 43801873348}, 258, 'package_route_boundary')

    verify_local_opnsense_baseline()
    verify_semantic_review()
