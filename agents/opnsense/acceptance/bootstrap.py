"""Install the current unsigned package on a new signed OPNsense CI guest."""
import argparse
import json
import os
from pathlib import Path
import re
import sys

from guest import Guest, GuestError, download, digest, invoke, supported_platform


ROOT = Path(__file__).resolve().parents[3]
SDK = 'go1.26.10.freebsd-amd64.tar.gz'
SDK_SHA256 = '3f47779b4534a578f9d4d3c263455574f073d6f0e382684ec3c1c08eadb4aaff'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--deployment-stage', type=Path)
    parser.add_argument('--console-port', type=int)
    parser.add_argument('--project')
    args = parser.parse_args()
    if any(value is not None for value in (args.deployment_stage, args.console_port, args.project)) and not all(
            value is not None for value in (args.deployment_stage, args.console_port, args.project)):
        raise GuestError('Complete owned deployment binding required')
    directory, evidence = args.directory.absolute(), args.evidence.absolute()
    if directory != directory.resolve() or evidence != evidence.resolve():
        raise GuestError('Aliased acceptance storage refused')
    directory.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    result = {'source_head': os.environ['NETHUB_SOURCE_HEAD'], 'passed': False,
              'scope': 'Fresh installed package and native page preparation',
              'full_rotation_acceptance': False, 'formal_release': False,
              'public_network_acceptance': False, 'full_goal_complete': False}
    owned = None
    try:
        actual = invoke(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], 'source identity').decode().strip()
        if not re.fullmatch(r'[a-f0-9]{40}', result['source_head']) or actual != result['source_head']:
            raise GuestError('Acceptance source head differs')
        invoke(['git', '-C', str(ROOT), 'diff', '--exit-code', 'HEAD'], 'clean source verification')
        if (ROOT / 'server/.go-version').read_text(encoding='ascii').strip() != '1.26.10':
            raise GuestError('Pinned guest SDK needs explicit compiler update')
        source = directory / 'source.tar'
        source.write_bytes(invoke(['git', '-C', str(ROOT), '-c', 'core.autocrlf=false',
                                  'archive', '--format=tar', 'HEAD'], 'tracked source archive'))
        result['source_archive_sha256'] = digest(source)
        sdk = directory / SDK
        result['phase'] = 'pinned_sdk'
        download('https://go.dev/dl/' + SDK, sdk, 128 * 1024**2)
        if digest(sdk) != SDK_SHA256:
            raise GuestError('Pinned guest compiler checksum differs')
        result['phase'] = 'signed_guest'
        owned = Guest(directory / 'guest')
        with owned as guest:
            result['image'] = guest.image_receipt
            result['guest_memory_mib'] = 3072
            result['phase'] = 'signed_package_update'
            guest.console.command('set -eu\npkg update -f\npkg upgrade -y\n', timeout=900)
            guest.ensure_ssh()
            version = guest.ssh('/usr/local/sbin/opnsense-version -v\n', 'installed platform version').decode().strip()
            if not supported_platform(version):
                raise GuestError('Guest has not reached the required patched 26.7 platform')
            result['opnsense_version'] = version
            result['phase'] = 'native_package_build'
            guest.put(source, 'source.tar')
            guest.put(sdk, 'toolchain.tar.gz')
            build = '''set -eu
umask 077
mkdir /root/nethub-ci/source /root/nethub-ci/toolchain
tar -xf /root/nethub-ci/source.tar -C /root/nethub-ci/source
tar -xzf /root/nethub-ci/toolchain.tar.gz -C /root/nethub-ci/toolchain
PATH=/root/nethub-ci/toolchain/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
export PATH
sh /root/nethub-ci/source/agents/opnsense/plugin/build.sh
'''
            guest.ssh(build, 'native unsigned package build', timeout=1000)
            guest.console.command('pkg add /root/nethub-ci/source/agents/opnsense/plugin/dist/os-nethub-agent.pkg\n', timeout=180)
            guest.ensure_ssh()
            inspect = '''set -eu
pkg info -e os-nethub-agent
/usr/local/opnsense/nethub-agent/bin/frpc --version
/usr/local/bin/python3.13 - <<'PY'
import hashlib,json,pathlib,subprocess
p=pathlib.Path('/usr/local/opnsense/nethub-agent/bin')
r=json.loads((p/'FRP_BUILD.json').read_text())
assert r['compiler']=='go1.26.10' and r['frp_version']=='0.71.1'
assert hashlib.sha256((p/'frpc').read_bytes()).hexdigest()==r['binary_sha256']
status=json.loads(subprocess.check_output(['/usr/local/sbin/configctl','nethub-agent','status']))
assert status['status']=='stopped' and status['revoked'] is False
print(json.dumps({'native_status':'stopped','frpc_sha256':r['binary_sha256'],'frpc_compiler':r['compiler'],'frp_version':r['frp_version']}))
PY
'''
            response = guest.ssh(inspect, 'installed client and configd verification').decode().splitlines()
            if response[0] != '0.71.1':
                raise GuestError('Installed client version differs')
            result['installed'] = json.loads(response[-1])
            result['phase'] = 'native_page'
            config = directory / 'browser-private.json'
            config.write_text(json.dumps({'origin': f'https://127.0.0.1:{guest.gui_port}',
                                          'evidence': str(evidence)}), encoding='utf-8')
            config.chmod(0o600)
            invoke([os.environ['NETHUB_NODE_BINARY'], str(Path(__file__).with_name('bootstrap-browser.mjs')),
                    str(config)], 'installed native page browser check', timeout=90)
            page = json.loads((evidence / 'page.json').read_text(encoding='utf-8'))
            if page['passed'] is not True:
                raise GuestError('Installed native page was not confirmed')
            result['page'] = page
            result['unsigned_package_installed'] = True
            if args.deployment_stage is not None:
                from enrolled import exercise
                result['phase'] = 'installed_enrollment_rotation'
                result['installed_rotation'] = exercise(guest, args.deployment_stage, args.console_port,
                                                       args.project, evidence)
            result['passed'] = True
            result['phase'] = 'completed'
    except Exception as error:
        result['failure'] = str(error) if isinstance(error, GuestError) else type(error).__name__
        raise
    finally:
        if owned is not None:
            result['guest_diagnostic'] = owned.diagnostics()
        (evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('Fresh OPNsense package and native page preparation passed; enrollment/rotation/relay acceptance remains separate')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Native installed package preparation failed: ' +
              (str(error) if isinstance(error, GuestError) else type(error).__name__), file=sys.stderr)
        raise SystemExit(1)
