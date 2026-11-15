#!/usr/bin/env python3
"""Check the committed handoff's integrity and recorded outcome boundaries."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import zipfile


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def checked_path(root, relative):
    name = PurePosixPath(relative)
    if name.is_absolute() or '..' in name.parts or '\\' in relative or name.as_posix() != relative:
        raise ValueError('Noncanonical handoff path')
    path = root / relative
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Missing or aliased handoff file: ' + relative)
    return path


def verify(root):
    evidence = root / 'docs/handoff/evidence'
    index = load(evidence / 'index.json')
    requirements = load(root / 'docs/handoff/remaining-work.json')
    assert index['version'] == 1 and index['owner_requested_stop'] is True
    assert index['full_project_complete'] is False and requirements['full_project_complete'] is False
    rows = requirements['requirements']
    assert len(rows) == len({v['id'] for v in rows}) == 29
    assert all(v['status'] and v['evidence_scope'] and v['next_action'] for v in rows)
    names = set()
    public_manifest_hashes_checked = 0
    for item in index['files']:
        assert item['path'] not in names
        names.add(item['path'])
        path = checked_path(evidence, item['path'])
        assert 0 < path.stat().st_size == item['bytes'] <= 16 * 1024**2
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256']
    for run in index['runs']:
        source = index['code_snapshots'][run['source']]
        assert re.fullmatch('[a-f0-9]{40}', source['head']) and run['source_head'] == source['head']
        assert source[run['kind']] == run['id'] and run['attempt'] >= 1
        expected = 'failure' if run['kind'] == 'native' else 'success'
        assert run['conclusion'] == expected
        for job in run['jobs']:
            assert re.fullmatch('[a-f0-9]{64}', job['decoded_log_sha256'])
            assert job['decoded_log_bytes'] > 100
        if run['kind'] == 'CI':
            assert len(run['jobs']) == 6 and all(j['conclusion'] == 'success' for j in run['jobs'])
        for artifact in run['artifacts']:
            if not artifact['full_archive_in_repository']:
                continue
            path = checked_path(evidence, artifact['path'])
            assert path.stat().st_size == artifact['bytes']
            assert 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest() == artifact['digest']
            with zipfile.ZipFile(path) as archive:
                inventory = archive.namelist()
                assert inventory and len(inventory) == len(set(inventory))
                assert sum(i.file_size for i in archive.infolist()) <= 16 * 1024**2
                assert all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and '\\' not in n for n in inventory)
                if run['kind'] == 'native':
                    native = json.loads(archive.read('native/result.json'))
                    assert native['source_head'] == source['head'] and native['passed'] is False and native['failure']
                    if run['source'] == 'source72':
                        package = json.loads(archive.read('native/installed-package-migration.json'))
                        assert package['passed'] is False and package['phase'] == 'upgrade'
                        assert [v['phase'] for v in package['steps']] == ['baseline', 'widen', 'offline_rollback', 'rollback', 'legacy_recovered', 'legacy_steady', 'offline_upgrade']
                        assert len(package['outages']) == 2
                elif run['kind'] == 'cold':
                    cold = json.loads(archive.read('result.json'))
                    assert cold['source_head'] == source['head'] and cold['accepted_ci_run'] == source['CI']
                    assert cold['passed'] is True and cold['full_goal_complete'] is False
                    assert cold['cleanup']['operation_cgroup_reaped'] is True
                    assert cold['cleanup']['owned_private_VM_disks_keys_and_logs_removed'] is True
                    for name, digest in cold['screenshots'].items():
                        assert hashlib.sha256(archive.read(name)).hexdigest() == digest
                elif run['kind'] == 'filesystem':
                    manifest = json.loads(archive.read('source.json'))
                    assert manifest['source_head'] == source['head'] and len(manifest['files']) == 256
                    # A generic key scanner can mistake these public file hashes
                    # for credentials because the filenames contain key/token.
                    public_names = {'certificate_key.py', 'certificate-key-progress.md',
                                    'test_certificate_key.py', 'test_gui_key_binding.py',
                                    'test_native_shared_token.py', 'missing-token.json',
                                    'null-gui-key.json', 'padded-gui-key.json',
                                    'rotate-noncanonical-secret.json'}
                    matches = {name: digest for name, digest in manifest['files'].items()
                               if PurePosixPath(name).name in public_names}
                    assert len(matches) == 9
                    for name, digest in matches.items():
                        raw = subprocess.check_output(['git', '-C', str(root), 'show', source['head'] + ':' + name], timeout=30)
                        assert hashlib.sha256(raw).hexdigest() == digest
                        public_manifest_hashes_checked += 1
    patches = root / 'docs/handoff/patches'
    for item in load(patches / 'index.json')['files']:
        path = checked_path(patches, item['path'])
        assert path.stat().st_size == item['bytes']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256']
    assert public_manifest_hashes_checked == 18
    print(f"Verified {len(index['files'])} evidence files, {len(index['runs'])} original runs, four patches and all 29 requirement rows.")
    print('Verified 18 key/token-named manifest entries against public source bytes; they are SHA256 file hashes, not credentials.')
    print('Recorded native failures remain failures. This is integrity checking, not a new runtime or release acceptance.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    verify(args.root.resolve(strict=True))
