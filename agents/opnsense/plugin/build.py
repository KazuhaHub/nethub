"""Stage an unsigned development package using the host FreeBSD pkg tools."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from frp_artifact import read_lock
from frpc_source import build as build_frpc


def build(version):
    root = Path(__file__).resolve().parent
    metadata = root / 'packaging/freebsd'
    source = root / 'src'
    product = json.loads((source / 'usr/local/opnsense/version/nethub-agent').read_text())
    if product['product_version'] != version:
        raise ValueError('build.sh VERSION and product_version differ')
    if subprocess.check_output(['uname', '-s'], text=True).strip() != 'FreeBSD':
        raise RuntimeError('FreeBSD is required')
    if any(path.is_symlink() for path in source.rglob('*')):
        raise ValueError('Package source must not contain symlinks')
    with tempfile.TemporaryDirectory(prefix='nethub-package-') as temporary:
        work = Path(temporary)
        stage, meta = work / 'stage', work / 'metadata'
        shutil.copytree(source, stage, ignore=shutil.ignore_patterns('.DS_Store', '._*', '__pycache__'))
        frpc = stage / 'usr/local/opnsense/nethub-agent/bin/frpc'
        build_frpc(frpc)
        expected = read_lock()['version']
        if subprocess.check_output([str(frpc), '--version'], text=True).strip() != expected:
            raise ValueError('Rebuilt frpc reports an unexpected version')
        (frpc.parent / 'FRP_VERSION').write_text(expected + '\n')
        meta.mkdir()
        abi = subprocess.check_output(['pkg', 'config', 'ABI'], text=True).strip()
        if subprocess.check_output(['uname', '-m'], text=True).strip() != 'amd64':
            raise RuntimeError('The W1 package targets amd64 only')
        parts = abi.split(':')
        if len(parts) != 3 or parts[0] != 'FreeBSD' or not parts[1].isdigit() or parts[2] != 'amd64':
            raise ValueError('Unexpected native pkg ABI: ' + abi)
        arch = 'freebsd:' + parts[1] + ':x86:64'
        text = (metadata / '+MANIFEST.in').read_text()
        for key, value in {'VERSION': version, 'ABI': abi, 'ARCH': arch}.items():
            text = text.replace('@' + key + '@', value)
        manifest = json.loads(text)
        manifest['desc'] = (metadata / 'pkg-descr').read_text().strip()
        manifest['scripts'] = {key: (metadata / name).read_text() for key, name in {
            'pre-install': '+PRE_INSTALL', 'post-install': '+POST_INSTALL',
            'pre-deinstall': '+PRE_DEINSTALL', 'post-deinstall': '+POST_DEINSTALL',
        }.items()}
        files = sorted(path for path in stage.rglob('*') if path.is_file())
        for path in stage.rglob('*'):
            if path.is_symlink():
                raise ValueError('Package source must not contain symlinks')
            path.chmod(0o755 if path.is_dir() else 0o644)
        frpc.chmod(0o755)
        for name in ['usr/local/etc/rc.d/nethub_agent_frpc',
                     'usr/local/etc/rc.syshook.d/early/15-nethub-agent-certificate',
                     'usr/local/etc/rc.syshook.d/start/20-nethub-agent']:
            path = stage / name
            if path.exists():
                path.chmod(0o755)
        manifest['flatsize'] = sum(path.stat().st_size for path in files)
        (meta / '+MANIFEST').write_text(json.dumps(manifest))
        plist = work / 'pkg-plist'
        plist.write_text(''.join('/' + path.relative_to(stage).as_posix() + '\n' for path in files))
        output = work / 'output'
        output.mkdir()
        subprocess.run(['pkg', 'create', '-m', str(meta), '-r', str(stage), '-p', str(plist), '-o', str(output)], check=True)
        package = output / ('os-nethub-agent-' + version + '.pkg')
        subprocess.run(['pkg', 'info', '-F', str(package)], check=True)
        dist = root / 'dist'
        dist.mkdir(exist_ok=True)
        shutil.copy2(package, dist / 'os-nethub-agent.pkg')
        print('Unsigned development package: ' + str(dist / 'os-nethub-agent.pkg'))


if __name__ == '__main__':
    build(sys.argv[1])
