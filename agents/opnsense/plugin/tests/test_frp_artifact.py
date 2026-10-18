"""Reject corrupt archives and wrong-platform binaries before replacing files."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('frp_artifact', ROOT / 'frp_artifact.py')
FRP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FRP)


def bundle(tmp_path, *, abi=9, machine=62, link=False, duplicate=False):
    header = bytearray(64)
    header[:8] = b'\x7fELF\x02\x01\x01' + bytes([abi])
    header[16:20] = bytes([2, 0, machine, 0])
    archive = tmp_path / 'release.tar.gz'
    with tarfile.open(archive, 'w:gz') as output:
        for _ in range(2 if duplicate else 1):
            member = tarfile.TarInfo('frp_0.71.1_freebsd_amd64/frpc')
            if link:
                member.type = tarfile.SYMTYPE
                member.linkname = '../../other'
                output.addfile(member)
            else:
                member.size = len(header)
                output.addfile(member, io.BytesIO(header))
    return archive, {'version': '0.71.1', 'archives': {
        'freebsd_amd64': hashlib.sha256(archive.read_bytes()).hexdigest()}}


def test_version_pins_agree():
    root = ROOT.parents[2]
    assert FRP.read_lock()['version'] == (root / 'deploy/frp/FRP_VERSION').read_text().strip()


def test_expected_binary_is_staged(tmp_path):
    archive, lock = bundle(tmp_path)
    output = tmp_path / 'bin/frpc'
    FRP.stage_binary(archive, output, 'freebsd_amd64', 'frpc', lock)
    assert output.read_bytes().startswith(b'\x7fELF')


@pytest.mark.parametrize('change', ['checksum', 'os', 'machine', 'link', 'duplicate', 'missing'])
def test_invalid_payload_preserves_installed_binary(tmp_path, change):
    archive, lock = bundle(tmp_path, abi=0 if change == 'os' else 9,
                           machine=183 if change == 'machine' else 62,
                           link=change == 'link', duplicate=change == 'duplicate')
    if change == 'checksum':
        lock['archives']['freebsd_amd64'] = '0' * 64
    output = tmp_path / 'frpc'
    output.write_bytes(b'previous binary')
    with pytest.raises(ValueError):
        FRP.stage_binary(archive, output, 'freebsd_amd64',
                         'frps' if change == 'missing' else 'frpc', lock)
    assert output.read_bytes() == b'previous binary'
    assert not list(tmp_path.glob('.frp-*'))
