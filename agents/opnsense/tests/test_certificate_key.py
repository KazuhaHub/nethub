"""Exercise actual OpenSSL keys and private-store crash/permission boundaries."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'agents/opnsense/plugin/src/usr/local/opnsense/scripts/nethub-agent/certificate_key.py'
sys.path.insert(0, str(SOURCE.parent))
SPEC = importlib.util.spec_from_file_location('nethub_certificate_key', SOURCE)
KEY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KEY)
OPENSSL = shutil.which('openssl')
pytestmark = pytest.mark.skipif(OPENSSL is None, reason='OpenSSL is required for real key validation')


@pytest.fixture
def store(tmp_path):
    parent = tmp_path / 'private'
    parent.mkdir(mode=0o700)
    return KEY.KeyStore(parent / 'gui-key', openssl=OPENSSL)


def test_key_is_durable_private_and_unchanged_on_retry(store):
    value = store.ensure()
    path = store.directory / 'key.pem'
    original, inode = path.read_bytes(), path.stat().st_ino
    metadata = (store.directory / 'state.json').read_bytes()
    assert set(value) == {'version', 'public_key', 'fingerprint'}
    assert 'PRIVATE' not in json.dumps(value) and len(value['public_key']) == 122
    assert value['fingerprint'] == KEY.gui_key_fingerprint(value['public_key'])
    assert store.ensure() == value
    assert path.read_bytes() == original and path.stat().st_ino == inode
    assert (store.directory / 'state.json').read_bytes() == metadata
    if hasattr(os, 'geteuid'):
        assert store.directory.stat().st_mode & 0o777 == 0o700
        assert path.stat().st_mode & 0o777 == 0o600
        assert (store.directory / 'state.json').stat().st_mode & 0o777 == 0o600
    # Public values and paths are the only arguments; key material is never argv.
    with mock.patch.object(KEY.subprocess, 'run', wraps=subprocess.run) as run:
        assert store.ensure() == value
    assert all('PRIVATE KEY' not in str(call.args) for call in run.call_args_list)


@pytest.mark.parametrize('missing', ['key.pem', 'state.json', 'both'])
def test_existing_incomplete_store_never_generates_a_replacement(store, missing):
    store.ensure()
    for name in ['key.pem', 'state.json'] if missing == 'both' else [missing]:
        (store.directory / name).unlink()
    with mock.patch.object(KEY.subprocess, 'run') as run:
        with pytest.raises(KEY.CertificateKeyError):
            store.ensure()
    run.assert_not_called()


@pytest.mark.parametrize('mutation', ['duplicate', 'unknown', 'fingerprint', 'public-point', 'extra-file'])
def test_corrupt_binding_is_not_rewritten(store, mutation):
    store.ensure()
    key = (store.directory / 'key.pem').read_bytes()
    path = store.directory / 'state.json'
    data = json.loads(path.read_bytes())
    if mutation == 'duplicate':
        path.write_bytes(path.read_bytes().replace(b'"version":1', b'"version":1,"version":1'))
    elif mutation == 'extra-file':
        (store.directory / 'unknown').write_text('retain')
    else:
        if mutation == 'unknown':
            data['other'] = True
        elif mutation == 'fingerprint':
            data['fingerprint'] = '0'*64
        else:
            data['public_key'] = 'A'*122
        path.write_bytes(store._encoded(data))
    before = path.read_bytes()
    with pytest.raises(KEY.CertificateKeyError):
        store.ensure()
    assert path.read_bytes() == before and (store.directory / 'key.pem').read_bytes() == key


def test_changed_private_key_fails_instead_of_changing_binding(store, tmp_path):
    store.ensure()
    other = tmp_path / 'other'
    other.mkdir(mode=0o700)
    second = KEY.KeyStore(other / 'gui-key', openssl=OPENSSL)
    second.ensure()
    changed = (second.directory / 'key.pem').read_bytes()
    (store.directory / 'key.pem').write_bytes(changed)
    with pytest.raises(KEY.CertificateKeyError, match='differs from its saved binding'):
        store.ensure()
    assert (store.directory / 'key.pem').read_bytes() == changed


@pytest.mark.parametrize('kind', ['two-keys', 'comment', 'crlf'])
def test_ambiguous_private_encoding_is_rejected_without_rewrite(store, kind):
    store.ensure()
    path = store.directory / 'key.pem'
    data = path.read_bytes()
    if kind == 'two-keys':
        data += data
    elif kind == 'comment':
        data = b'comment\n'+data
    else:
        data = data.replace(b'\n', b'\r\n')
    path.write_bytes(data)
    with pytest.raises(KEY.CertificateKeyError):
        store.ensure()
    assert path.read_bytes() == data


def test_prepublication_failure_removes_only_its_unpublished_files(store):
    with mock.patch.object(KEY.os, 'rename', side_effect=OSError('private failure')):
        with pytest.raises(KEY.CertificateKeyError) as error:
            store.ensure()
    assert 'private failure' not in str(error.value)
    assert not store.directory.exists()
    assert list(store.directory.parent.iterdir()) == []


def test_postpublication_sync_failure_retains_same_key(store):
    sync = store._sync
    def fail(path):
        if path == store.directory.parent:
            raise OSError('private failure')
        sync(path)
    with mock.patch.object(store, '_sync', side_effect=fail):
        with pytest.raises(KEY.CertificateKeyError):
            store.ensure()
    before = (store.directory / 'key.pem').read_bytes()
    with mock.patch.object(KEY.subprocess, 'run', wraps=subprocess.run) as run:
        store.ensure()
    assert all('genpkey' not in call.args[0] for call in run.call_args_list)
    assert (store.directory / 'key.pem').read_bytes() == before


def test_openssl_failure_does_not_echo_output_or_leave_published_key(store):
    with mock.patch.object(KEY.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'private child output', b'private stderr')):
        with pytest.raises(KEY.CertificateKeyError) as error:
            store.ensure()
    assert 'private' not in str(error.value).lower()
    assert list(store.directory.parent.iterdir()) == []


def test_explicit_removal_is_idempotent_and_recovers_interrupted_key_unlink(store):
    store.ensure()
    (store.directory / 'key.pem').unlink()
    with pytest.raises(KEY.CertificateKeyError):
        store.ensure()
    store.forget()
    store.forget()
    assert not store.directory.exists()
    assert len(store.ensure()['public_key']) == 122


@pytest.mark.skipif(os.name != 'posix', reason='Production POSIX ownership/link checks')
@pytest.mark.parametrize('kind', ['key-symlink', 'key-hardlink', 'metadata-symlink', 'key-mode', 'metadata-mode', 'directory-mode', 'parent-alias'])
def test_unsafe_paths_are_retained_for_review(store, tmp_path, kind):
    store.ensure()
    key, state = store.directory / 'key.pem', store.directory / 'state.json'
    outside = tmp_path / 'outside'
    outside.write_bytes(key.read_bytes())
    outside.chmod(0o600)
    if kind == 'key-symlink':
        key.unlink(); key.symlink_to(outside)
    elif kind == 'key-hardlink':
        key.unlink(); os.link(outside, key)
    elif kind == 'metadata-symlink':
        state.unlink(); state.symlink_to(outside)
    elif kind == 'key-mode':
        key.chmod(0o644)
    elif kind == 'metadata-mode':
        state.chmod(0o644)
    elif kind == 'directory-mode':
        store.directory.chmod(0o755)
    else:
        alias = tmp_path / 'alias'
        alias.symlink_to(store.directory.parent, target_is_directory=True)
        store = KEY.KeyStore(alias / 'gui-key', openssl=OPENSSL)
    original = outside.read_bytes()
    with pytest.raises(KEY.CertificateKeyError):
        store.ensure()
    with pytest.raises(KEY.CertificateKeyError):
        store.forget()
    assert outside.read_bytes() == original
