"""Verify frpc, frps, and the pinned os-frp source use the same official release."""
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'agents/opnsense/plugin'))
from frp_artifact import read_lock


def read_url(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        payload = response.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise ValueError('Version reference exceeds size limit')
    return payload


def verify():
    lock = read_lock()
    version = lock['version']
    if (ROOT / 'deploy/frp/FRP_VERSION').read_text().strip() != version:
        raise ValueError('Relay and device versions differ')
    manifest = read_url(f'https://github.com/fatedier/frp/releases/download/v{version}/frp_sha256_checksums.txt')
    if hashlib.sha256(manifest).hexdigest() != lock['checksums_sha256']:
        raise ValueError('Official checksum manifest changed')
    checksums = {line.split()[1]: line.split()[0] for line in manifest.decode().splitlines()}
    for platform, digest in lock['archives'].items():
        if checksums.get(f'frp_{version}_{platform}.tar.gz') != digest:
            raise ValueError('Artifact pin differs from the official checksum manifest')
    base = f"https://raw.githubusercontent.com/KKazuhaK/OPNsense-repo/{lock['os_frp_commit']}"
    source_version = read_url(base + '/src/os-frp/FRP_VERSION').decode().strip()
    registry = json.loads(read_url(base + '/packaging/plugins.json'))['plugins']['os-frp']
    if source_version != version:
        raise ValueError('os-frp and NetHub versions differ')
    archive = registry['vendored'][0]
    if (archive['artifact'] != f'vendor/frp_{version}_freebsd_amd64.tar.gz'
            or archive['sha256'] != lock['archives']['freebsd_amd64']):
        raise ValueError('os-frp archive and NetHub archive differ')
    print(f'frpc, frps, and pinned os-frp source agree on {version}; official checksums verified')


if __name__ == '__main__':
    verify()
