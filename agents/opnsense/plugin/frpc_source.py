"""Build the appliance client from the audited module and compiler locks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from frp_artifact import read_lock, verify_elf

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[2]
MODULE = ROOT / 'frpc-build'
PACKAGE = 'github.com/fatedier/frp/cmd/frpc'


def check_build_info(raw, compiler, version):
    lines = raw.splitlines()
    if not lines or lines[0].split()[-1] != compiler:
        raise ValueError('Client compiler does not match the pinned version')
    records = [line.split() for line in lines[1:]]
    paths = [row[1:] for row in records if row and row[0] == 'path']
    modules = [row[1:] for row in records if row and row[0] == 'mod']
    settings = dict(row[1].split('=', 1) for row in records if len(row) == 2 and row[0] == 'build')
    if paths != [[PACKAGE]] or len(modules) != 1 or modules[0][:2] != ['github.com/fatedier/frp', 'v'+version]:
        raise ValueError('Client source identity does not match the pinned version')
    for name, expected in {'GOOS': 'freebsd', 'GOARCH': 'amd64', 'GOAMD64': 'v1',
                           'CGO_ENABLED': '0', '-tags': 'frpc,noweb'}.items():
        if settings.get(name) != expected:
            raise ValueError('Client target or feature profile does not match')


def build(output):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('Client output must be new')
    go = shutil.which('go')
    if go is None:
        raise ValueError('The pinned Go compiler is required to build frpc')
    compiler = 'go'+(REPOSITORY/'server/.go-version').read_text().strip()
    version = read_lock()['version']
    env = dict(os.environ, GOENV='off', GOWORK='off', GOTOOLCHAIN='local', GOOS='freebsd', GOARCH='amd64',
               GOAMD64='v1', GOEXPERIMENT='',
               CGO_ENABLED='0', GOFLAGS='-mod=readonly -tags=frpc,noweb', GOMAXPROCS='2', GOMEMLIMIT='384MiB')
    # The license collector invokes go itself; keep that command on the same SDK.
    env['PATH'] = str(Path(go).parent)+os.pathsep+env.get('PATH', '')

    def run(args, *, environment=env, timeout=600):
        return subprocess.check_output(args, cwd=MODULE, env=environment, timeout=timeout, text=True)

    if run([go, 'env', 'GOVERSION']).strip() != compiler:
        raise ValueError('The installed Go compiler differs from server/.go-version')
    locks = {name: hashlib.sha256((MODULE/name).read_bytes()).hexdigest() for name in ('go.mod', 'go.sum')}
    run([go, 'mod', 'verify'])
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.frpc-build-', dir=output.parent) as temporary:
        work = Path(temporary)
        binary = work/'frpc'
        run([go, 'build', '-p', '2', '-trimpath', '-buildvcs=false', '-o', str(binary), PACKAGE])
        with binary.open('rb') as source:
            verify_elf(source.read(20), 'freebsd_amd64')
        check_build_info(run([go, 'version', '-m', str(binary)]), compiler, version)
        host = dict(env, GOOS=run([go, 'env', 'GOHOSTOS']).strip(),
                    GOARCH=run([go, 'env', 'GOHOSTARCH']).strip(), GOFLAGS='-mod=readonly')
        collector = work/('license-collector.exe' if host['GOOS'] == 'windows' else 'license-collector')
        run([go, 'build', '-p', '2', '-trimpath', '-o', str(collector),
             str(REPOSITORY/'deploy/images/licenses.go')], environment=host)
        licenses = work/'licenses'
        run([str(collector), PACKAGE, str(licenses)])
        goroot = Path(run([go, 'env', 'GOROOT']).strip())
        shutil.copyfile(goroot/'LICENSE', licenses/'GO-LICENSE')
        upstream = licenses/('github.com/fatedier/frp@v'+version)/'LICENSE'
        if not upstream.is_file():
            raise ValueError('The upstream client license is missing')
        run([go, 'mod', 'verify'])
        if any(hashlib.sha256((MODULE/name).read_bytes()).hexdigest() != digest for name, digest in locks.items()):
            raise ValueError('Client dependency locks changed during the build')
        receipt = {'compiler': compiler, 'frp_version': version, 'target': 'freebsd_amd64',
                   'tags': ['frpc', 'noweb'], 'dependency_locks': locks,
                   'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
        shutil.copytree(licenses, output.parent/'frpc-licenses')
        shutil.copyfile(upstream, output.parent/'FRP_LICENSE')
        (output.parent/'FRP_BUILD.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')
        binary.chmod(0o755)
        os.replace(binary, output)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    print(json.dumps(build(parser.parse_args().output), sort_keys=True))
