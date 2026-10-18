"""Fetch a pinned official frp executable without extracting archive paths."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 64 * 1024 * 1024


def read_lock():
    lock = json.loads((ROOT / 'frp-artifacts.json').read_text(encoding='utf-8'))
    if lock['version'] != (ROOT / 'FRP_VERSION').read_text().strip():
        raise ValueError('frp artifact lock and FRP_VERSION differ')
    return lock


def download(url, target):
    with urllib.request.urlopen(url, timeout=60) as response, target.open('wb') as output:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_ARCHIVE:
                raise ValueError('frp archive exceeds size limit')
            output.write(chunk)


def verify_elf(header, platform):
    expected_abi = 9 if platform == 'freebsd_amd64' else 0
    if (len(header) < 20 or header[:7] != b'\x7fELF\x02\x01\x01'
            or header[7] != expected_abi
            or struct.unpack('<HH', header[16:20]) not in [(2, 62), (3, 62)]):
        raise ValueError('frp binary is not the expected amd64 ELF executable')


def stage_binary(archive, output, platform, binary, lock):
    if platform not in lock['archives'] or binary not in ('frpc', 'frps'):
        raise ValueError('Unsupported frp platform or executable')
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError('frp archive exceeds size limit')
    with archive.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    if digest != lock['archives'][platform]:
        raise ValueError('frp archive SHA256 mismatch')
    member_name = f"frp_{lock['version']}_{platform}/{binary}"
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, 'r:gz') as bundle:
        matches = [member for member in bundle.getmembers() if member.name == member_name]
        if len(matches) != 1 or not matches[0].isfile() or not 20 <= matches[0].size <= MAX_BINARY:
            raise ValueError('frp archive must contain exactly one regular executable')
        with bundle.extractfile(matches[0]) as source:
            header = source.read(20)
            verify_elf(header, platform)
            descriptor, name = tempfile.mkstemp(prefix='.frp-', dir=output.parent)
            temporary = Path(name)
            try:
                with os.fdopen(descriptor, 'wb') as destination:
                    destination.write(header)
                    shutil.copyfileobj(source, destination)
                    destination.flush()
                    os.fsync(destination.fileno())
                temporary.chmod(0o755)
                os.replace(temporary, output)
            finally:
                temporary.unlink(missing_ok=True)


def stage_license(archive, output, platform, lock):
    name = f"frp_{lock['version']}_{platform}/LICENSE"
    with tarfile.open(archive, 'r:gz') as bundle:
        member = bundle.getmember(name)
        if not member.isfile() or not 0 < member.size <= 1024 * 1024:
            raise ValueError('Invalid upstream license member')
        with bundle.extractfile(member) as source:
            output.with_name('FRP_LICENSE').write_bytes(source.read())


def fetch(platform, binary, output, archive=None):
    lock = read_lock()
    if platform not in lock['archives']:
        raise ValueError('Unsupported frp platform')
    with tempfile.TemporaryDirectory(prefix='nethub-frp-') as work:
        if archive is None:
            archive = Path(work) / 'frp.tar.gz'
            name = f"frp_{lock['version']}_{platform}.tar.gz"
            download(f"https://github.com/fatedier/frp/releases/download/v{lock['version']}/{name}", archive)
        stage_binary(Path(archive), Path(output), platform, binary, lock)
        stage_license(Path(archive), Path(output), platform, lock)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=('freebsd_amd64', 'linux_amd64'), required=True)
    parser.add_argument('--binary', choices=('frpc', 'frps'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--archive', type=Path, help='Use a local archive with the same pinned checksum')
    options = parser.parse_args()
    fetch(options.platform, options.binary, options.output, options.archive)
