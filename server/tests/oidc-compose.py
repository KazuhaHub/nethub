"""Run genuine two-Dex browser admission against a fresh disposable deployment."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time


DEX_IMAGE = 'ghcr.io/dexidp/dex:v2.46.1@sha256:65b72ca0f4b0bf6d4ada84ec21da8851782563404ac7b8f926923d27ceced9ab'
ROOT = Path(__file__).resolve().parents[2]


class Failure(Exception):
    pass


def docker_project():
    # mkdtemp suffixes can end in '_' and are not valid image repositories.
    return 'nethub-oidc-' + os.urandom(8).hex()


def invoke(arguments, label, *, timeout=60, input=None, log=None, check=True):
    try:
        result = subprocess.run(arguments, input=input, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Failure(label + ' deadline exceeded') from None
    if log is not None:
        Path(log).write_bytes(result.stdout + result.stderr)
    if check and result.returncode:
        raise Failure(label + ' failed')
    return result


def docker_json(arguments, label):
    return json.loads(invoke(['docker', *arguments], label).stdout)


def archive_images(directory):
    directory = Path(directory).resolve(strict=True)
    sums = (directory / 'SHA256SUMS').read_text().strip()
    match = re.fullmatch(r'([a-f0-9]{64})  images\.tar\.gz', sums)
    if not match:
        raise Failure('image archive checksum format')
    with (directory / 'images.tar.gz').open('rb') as archive:
        digest = hashlib.file_digest(archive, 'sha256').hexdigest()
    if digest != match[1]:
        raise Failure('image archive checksum')
    images = json.loads((directory / 'images.json').read_text())
    if set(images) != {'runtime', 'postgres', 'caddy', 'frps'}:
        raise Failure('image archive service set')
    preexisting = set()
    for item in images.values():
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', item['id']) or not re.fullmatch(r'nethub-stack-test:tmp-[a-z0-9-]+', item['tag']):
            raise Failure('image identity format')
        prior = invoke(['docker', 'image', 'inspect', item['tag']], 'prior image inventory', check=False)
        if prior.returncode == 0:
            if json.loads(prior.stdout)[0]['Id'] != item['id']:
                raise Failure('refusing to retag an existing image')
            preexisting.add(item['tag'])
    return images, preexisting


def verify_loaded_images(images):
    for item in images.values():
        current = docker_json(['image', 'inspect', item['tag']], 'loaded image identity')[0]
        if current['Id'] != item['id'] or current['RootFS']['Layers'] != item['diff_ids'] or item['platform'] != current['Os'] + '/' + current['Architecture']:
            raise Failure('loaded image identity mismatch')


def require_empty_namespace(config, project):
    for group in ('networks', 'volumes'):
        if any(item.get('external') or not item.get('name', '').startswith(project + '_') for item in config[group].values()):
            raise Failure('SSO configuration escaped its owned resource namespace')
    existing = invoke(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project], 'prior SSO container inventory')
    if existing.stdout.strip():
        raise Failure('SSO project already has containers')
    for group, kind in [('networks', 'network'), ('volumes', 'volume')]:
        for item in config[group].values():
            if invoke(['docker', kind, 'inspect', item['name']], 'prior SSO resource inventory', check=False).returncode == 0:
                raise Failure('SSO resource name already exists')


def remove_image(reference, expected_id):
    current = invoke(['docker', 'image', 'inspect', reference], 'owned image cleanup identity', check=False)
    if current.returncode != 0 or json.loads(current.stdout)[0]['Id'] != expected_id:
        return False
    return invoke(['docker', 'image', 'rm', reference], 'owned image cleanup', check=False).returncode == 0


def dex_addresses(config):
    """Avoid dynamic allocation racing the deployment's reserved edge addresses."""
    pools = config['networks']['edge']['ipam']['config']
    if len(pools) != 1:
        raise Failure('SSO edge requires one IPv4 pool')
    network = ipaddress.ip_network(pools[0]['subnet'])
    if network.version != 4 or network.prefixlen < 24:
        raise Failure('SSO edge pool is not a bounded IPv4 subnet')
    used = {ipaddress.ip_address(pools[0]['gateway'])}
    for service in config['services'].values():
        address = service.get('networks', {}).get('edge', {}).get('ipv4_address')
        if address:
            used.add(ipaddress.ip_address(address))
    addresses = [str(address) for address in network.hosts() if address not in used]
    if len(addresses) < 2:
        raise Failure('SSO edge lacks two unreserved addresses')
    return dict(zip(('one', 'two'), addresses[:2]))


def startup_diagnostic(stage, raw):
    """Expose bounded pre-login tool errors after masking owned fixture secrets."""
    values = set()
    credentials = stage / 'fixture/credentials.json'
    if credentials.exists():
        data = json.loads(credentials.read_text())
        values.add(data['password'])
        values.update(data['clients'].values())
    for config in (stage / 'fixture').glob('dex-*.json'):
        values.update(user['hash'] for user in json.loads(config.read_text())['staticPasswords'])
    paths = list((stage / 'deployment/secrets').rglob('*'))
    paths += [stage / 'admin-password', stage / 'fixture/origin.key']
    for path in paths:
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= 131072:
            text = path.read_text(errors='replace').strip()
            values.add(text)
            values.update(line for line in text.splitlines() if len(line) >= 16)
    text = raw.decode(errors='replace')
    for value in sorted(values, key=len, reverse=True):
        if len(value) >= 8:
            text = text.replace(value, '[redacted]')
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    return text.replace(str(stage), '[owned stage]').replace(str(ROOT), '[checkout]')[-3000:]


def publish_evidence(directory):
    uid = int(os.environ.get('SUDO_UID', '0'))
    gid = int(os.environ.get('SUDO_GID', '0'))
    for name in ('dex-one-login.png', 'dex-two-login.png', 'results.json'):
        path = directory / name
        if path.exists():
            if not path.is_file() or path.is_symlink():
                raise Failure('unsafe public evidence path')
            os.chown(path, uid, gid)
    os.chown(directory, uid, gid)


def browser_diagnostic(failure):
    """Publish fixed categories and bounded scalars, never assertion strings."""
    result = {}
    for name in ('assertion_actual', 'assertion_expected'):
        value = failure.get(name)
        if type(value) is bool or type(value) is int and abs(value) <= 10000:
            result[name] = value
    for name, lower, upper in [('failure_line', 1, 100000), ('provider_status', 100, 599)]:
        value = failure.get(name)
        if type(value) is int and lower <= value <= upper:
            result[name] = value
    if failure.get('provider_error') in ('invalid_request', 'oidc_discovery_failed', 'forbidden', 'unauthenticated', 'internal_error', 'slug_taken'):
        result['provider_error'] = failure['provider_error']
    return result


def provider_diagnostic(value):
    result = {}
    for name in ('dns_resolved', 'metadata_issuer_matches', 'metadata_code_supported', 'metadata_signing_rs256', 'metadata_basic_auth', 'console_discovery_ok'):
        if type(value.get(name)) is bool:
            result[name] = value[name]
    status = value.get('discovery_status')
    if type(status) is int and 100 <= status <= 599:
        result['discovery_status'] = status
    categories = ('none', 'dns', 'certificate_authority', 'certificate_hostname', 'certificate_validity', 'deadline', 'console_outbound', 'console_discovery', 'console_auth_method', 'console_configuration', 'transport_or_protocol')
    for name in ('network_error', 'console_error'):
        if value.get(name) in categories:
            result[name] = value[name]
    return result


def main():
    if sys.platform != 'linux' or os.geteuid() != 0 or len(sys.argv) != 3:
        raise Failure('Linux root, accepted image archive and evidence directory required')
    os.umask(0o077)
    version = docker_json(['version', '--format', '{{json .Server.Version}}'], 'Docker readiness')
    if int(version.split('.')[0]) < 28:
        raise Failure('Docker 28 or newer required for loopback isolation')
    evidence = Path(sys.argv[2]).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    stage = Path(tempfile.mkdtemp(prefix='nethub-oidc-')).resolve()
    project = docker_project()
    helper_image = project + ':helper'
    holder = project + '-helper'
    images = {}
    preexisting = set()
    compose_file = stage / 'compose.json'
    helper_created = False
    helper_id = None
    holder_id = None
    successful = False
    browser_started = False
    dex_preexisting = invoke(['docker', 'image', 'inspect', DEX_IMAGE], 'Dex inventory', check=False).returncode == 0
    dex_id = None
    preflight = []
    result = {'passed': False, 'scope': 'fresh deployment with two real Dex providers', 'public_IdP_or_SAML_acceptance_claimed': False, 'provider_preflight': preflight}

    def compose(*arguments, timeout=60, input=None, check=True):
        label = 'owned SSO Compose ' + arguments[0]
        reply = invoke(['docker', 'compose', '-p', project, '-f', str(compose_file), *arguments], label, timeout=timeout, input=input, check=False)
        if check and reply.returncode:
            result['failed_compose_operation'] = arguments[0]
            if not browser_started and arguments[0] in ('up', 'run', 'ps'):
                diagnostic = startup_diagnostic(stage, reply.stderr)
                result['startup_diagnostic'] = diagnostic
                print('SSO startup diagnostic: ' + diagnostic, file=sys.stderr)
            raise Failure(label + ' failed')
        return reply

    try:
        images, preexisting = archive_images(sys.argv[1])
        invoke(['docker', 'load', '-i', str(Path(sys.argv[1]).resolve() / 'images.tar.gz')], 'verified image load', timeout=90)
        verify_loaded_images(images)
        if invoke(['docker', 'image', 'inspect', helper_image], 'prior fixture image inventory', check=False).returncode == 0:
            raise Failure('fixture image reference already exists')
        build = invoke(['docker', 'build', '--target', 'oidc-acceptance', '-f', str(ROOT / 'deploy/Dockerfile'), '-t', helper_image, str(ROOT)], 'OIDC fixture build', timeout=240, log=stage / 'helper-build.log', check=False)
        if build.returncode:
            # No fixture credentials exist yet; still use the bounded redactor.
            result['failed_preparation'] = 'fixture_build'
            result['startup_diagnostic'] = startup_diagnostic(stage, build.stdout + build.stderr)
            print('SSO preparation diagnostic: ' + result['startup_diagnostic'], file=sys.stderr)
            raise Failure('OIDC fixture build failed')
        helper_created = True
        helper_id = docker_json(['image', 'inspect', helper_image], 'fixture image identity')[0]['Id']
        holder_id = invoke(['docker', 'create', '--network', 'none', '--name', holder, '--label', 'org.nethub.test=' + project, helper_image, '/oidcfixture'], 'fixture extraction container').stdout.decode().strip()
        helper = stage / 'oidcfixture'
        invoke(['docker', 'cp', holder_id + ':/oidcfixture', str(helper)], 'fixture binary extraction')
        invoke(['docker', 'rm', holder_id], 'fixture extraction cleanup')
        holder_id = None
        helper.chmod(0o700)
        fixture = stage / 'fixture'
        invoke([str(helper), str(fixture)], 'fresh OIDC identities and TLS generation')
        for slug in ('one', 'two'):
            os.chown(fixture / ('dex-' + slug + '.json'), 65532, 65532)
        invoke(['docker', 'pull', '--platform', 'linux/amd64', DEX_IMAGE], 'pinned official Dex pull', timeout=120, log=stage / 'dex-pull.log')
        dex = docker_json(['image', 'inspect', DEX_IMAGE], 'Dex identity')[0]
        dex_id = dex['Id']
        if not any(value.endswith('@' + DEX_IMAGE.split('@')[1]) for value in dex['RepoDigests']):
            raise Failure('Dex registry digest mismatch')

        runtime = images['runtime']['tag']
        invoke(['docker', 'run', '--rm', '-i', '--network', 'none', '--user', '0', '-v', str(ROOT) + ':' + str(ROOT) + ':ro', '-v', str(stage) + ':' + str(stage), runtime,
                'init', '--offline', '--source-directory', str(ROOT), '--directory', str(stage / 'deployment'), '--backup-directory', str(stage / 'backup'), '--console-host', 'console.example.com', '--device-domain', 'router.example.com',
                '--oidc-private-host', 'dex-one.test', '--oidc-private-host', 'dex-two.test'], 'fresh SSO deployment initialization', timeout=90, input=b'I HAVE VERIFIED THE NETHUB SECRET BACKUP\n', log=stage / 'init.log')
        deployment = stage / 'deployment'
        raw = invoke(['docker', 'compose', '-p', project, '-f', str(deployment / 'docker-compose.yml'), '-f', str(deployment / 'docker-compose.override.yml'), '--profile', 'bootstrap', 'config', '--format', 'json'], 'SSO Compose normalization').stdout
        config = json.loads(raw)
        services = config['services']
        for service in ('migrate', 'nethub-web', 'nethub-authz', 'admin-bootstrap'):
            services[service]['image'] = runtime
        for service in ('postgres', 'caddy', 'frps'):
            services[service]['image'] = images[service]['tag']
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        caddy = services['caddy']
        caddy['ports'] = [{'host_ip': '127.0.0.1', 'published': str(port), 'target': 443, 'protocol': 'tcp'}]
        caddy['networks']['edge']['aliases'] = ['dex-one.test', 'dex-two.test']
        caddy_file = stage / 'Caddyfile'
        source = (ROOT / 'deploy/Caddyfile').read_text()
        if source.count('{$NETHUB_CONSOLE_HOST} {') != 1:
            raise Failure('console TLS route template changed')
        source = source.replace('{$NETHUB_CONSOLE_HOST} {', '''https://console.example.com {
    tls /fixture/origin.crt /fixture/origin.key
    respond /claim-probe "Signed claim captured" 200
    @captureCallback {
        path /api/v1/console/oidc/one/callback /api/v1/console/oidc/two/callback
        header X-Nethub-Test-Capture 1
    }
    respond @captureCallback "Callback captured" 200''', 1)
        for slug in ('one', 'two'):
            source += '\nhttps://dex-' + slug + '.test {\n    tls /fixture/origin.crt /fixture/origin.key\n    reverse_proxy dex-' + slug + ':5556\n}\n'
        caddy_file.write_text(source)
        caddy_file.chmod(0o644)
        for mount in caddy['volumes']:
            if mount['target'] == '/etc/caddy/Caddyfile':
                mount['source'] = str(caddy_file)
        for name in ('origin.crt', 'origin.key'):
            caddy['volumes'].append({'type': 'bind', 'source': str(fixture / name), 'target': '/fixture/' + name, 'read_only': True})
        web = services['nethub-web']
        web.setdefault('environment', {})['SSL_CERT_FILE'] = '/test-root.crt'
        web['volumes'].append({'type': 'bind', 'source': str(fixture / 'root.crt'), 'target': '/test-root.crt', 'read_only': True})
        addresses = dex_addresses(config)
        for slug in ('one', 'two'):
            services['dex-' + slug] = {'image': DEX_IMAGE, 'entrypoint': ['/usr/local/bin/dex'], 'command': ['serve', '/etc/dex/test.json'], 'user': '65532:65532', 'read_only': True,
                'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'pids_limit': 64, 'mem_limit': '192m',
                'tmpfs': ['/tmp:rw,nosuid,nodev,size=32m,mode=1777'], 'networks': {'edge': {'ipv4_address': addresses[slug]}},
                'volumes': [{'type': 'bind', 'source': str(fixture / ('dex-' + slug + '.json')), 'target': '/etc/dex/test.json', 'read_only': True}]}
        require_empty_namespace(config, project)
        for host, listening_port in [('0.0.0.0', 7000), ('0.0.0.0', 8443), ('127.0.0.1', 7500), ('127.0.0.1', 9000)]:
            with socket.socket() as listener:
                listener.bind((host, listening_port))
        compose_file.write_text(json.dumps(config))
        compose('up', '-d', '--no-build', '--wait', '--wait-timeout', '150', timeout=180)
        admin_password = stage / 'admin-password'
        admin_password.write_text(os.urandom(32).hex() + '\n')
        compose('run', '--rm', '-T', 'admin-bootstrap', '--email', 'compose-admin@example.com', '--password-stdin', timeout=90, input=admin_password.read_bytes())
        for host in ('console.example.com', 'dex-one.test', 'dex-two.test'):
            path = '/' if host == 'console.example.com' else '/.well-known/openid-configuration'
            ready = False
            for _ in range(20):
                response = invoke(['curl', '--fail', '--silent', '--show-error', '--noproxy', '*', '--cacert', str(fixture / 'root.crt'), '--connect-to', host + ':443:127.0.0.1:' + str(port), '--max-time', '3', 'https://' + host + path], 'SSO HTTPS readiness', timeout=5, check=False)
                if response.returncode == 0:
                    ready = True
                    break
                time.sleep(1)
            if not ready:
                raise Failure('SSO origin did not become ready with normal TLS verification')
        browser_home = stage / 'browser-home'
        database = browser_home / '.local/share/pki/nssdb'
        database.mkdir(parents=True)
        invoke(['certutil', '-N', '-d', 'sql:' + str(database), '--empty-password'], 'isolated browser trust initialization')
        invoke(['certutil', '-A', '-d', 'sql:' + str(database), '-n', project, '-t', 'C,,', '-i', str(fixture / 'root.crt')], 'isolated browser test-CA import')
        database_container = compose('ps', '-q', 'postgres').stdout.decode().strip()
        web_container = compose('ps', '-q', 'nethub-web').stdout.decode().strip()
        for slug in ('one', 'two'):
            holder_id = invoke(['docker', 'create', '--network', 'container:' + web_container, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--label', 'org.nethub.test=' + project, '--env', 'SSL_CERT_FILE=/fixture/root.crt',
                '--mount', 'type=bind,source=' + str(fixture / 'root.crt') + ',target=/fixture/root.crt,readonly',
                '--mount', 'type=bind,source=' + str(fixture / 'credentials.json') + ',target=/fixture/credentials.json,readonly',
                helper_image, '/oidcfixture', 'check-provider', '/fixture', slug], 'owned provider discovery diagnostic creation').stdout.decode().strip()
            diagnostic = invoke(['docker', 'start', '--attach', holder_id], 'owned provider discovery diagnostic', timeout=30)
            safe = dict(provider=slug, **provider_diagnostic(json.loads(diagnostic.stdout)))
            preflight.append(safe)
            print('SSO provider diagnostic: ' + json.dumps(safe))
            invoke(['docker', 'rm', holder_id], 'owned provider discovery diagnostic cleanup')
            holder_id = None
        browser_evidence = stage / 'browser'
        node = os.environ.get('NETHUB_NODE_BINARY', 'node')
        browser_started = True
        browser_result = invoke([node, str(ROOT / 'server/web/tests/oidc-deployment.mjs'), str(port), str(admin_password), str(fixture), str(helper), str(browser_home), str(browser_evidence), database_container, web_container], 'real Dex browser admission', timeout=240, log=stage / 'browser-private.log', check=False)
        if browser_result.returncode:
            failed = browser_evidence / 'results.json'
            if failed.exists():
                failure = json.loads(failed.read_text())
                phase = failure.get('phase', '')
                if re.fullmatch('[a-z_]{1,64}', phase):
                    result['failed_phase'] = phase
                    category = failure.get('category')
                    if category in ('assertion', 'certificate_trust', 'timeout', 'runtime'):
                        result['failed_category'] = category
                    result.update(browser_diagnostic(failure))
                    print('SSO browser diagnostic: ' + json.dumps(result), file=sys.stderr)
                    raise Failure('real Dex browser admission failed during ' + phase)
            raise Failure('real Dex browser admission failed')
        # The browser emits only fixed phase/check messages, never response URLs.
        print(browser_result.stdout.decode(), end='')
        result = json.loads((browser_evidence / 'results.json').read_text())
        result['provider_preflight'] = preflight
        private_values = json.loads((browser_evidence / 'privacy-values.json').read_text())
        logs = compose('logs', '--no-color').stdout.decode(errors='replace')
        if any(value in logs for value in private_values):
            raise Failure('authentication material appeared in deployed service logs')
        result['all_service_logs_checked_for_secret_absence'] = True
        result['dex_image'] = DEX_IMAGE
        result['deployed_images'] = {name: item['id'] for name, item in images.items()}
        for name in ('dex-one-login.png', 'dex-two-login.png'):
            shutil.copyfile(browser_evidence / name, evidence / name)
        successful = True
    finally:
        cleanup_ok = True
        if holder_id is not None:
            # A diagnostic can share Web's namespace; remove it before Compose
            # tears down that namespace and its owned networks.
            cleanup_ok = invoke(['docker', 'rm', '-f', holder_id], 'fixture holder cleanup', check=False).returncode == 0
        if compose_file.exists():
            cleanup_ok = compose('down', '-v', '--remove-orphans', timeout=90, check=False).returncode == 0 and cleanup_ok
            remaining = invoke(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project], 'owned SSO cleanup inventory', check=False)
            cleanup_ok = cleanup_ok and remaining.returncode == 0 and not remaining.stdout.strip()
            for kind in ('volume', 'network'):
                remaining = invoke(['docker', kind, 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project], 'owned SSO resource cleanup inventory', check=False)
                cleanup_ok = cleanup_ok and remaining.returncode == 0 and not remaining.stdout.strip()
        if helper_created:
            cleanup_ok = remove_image(helper_image, helper_id) and cleanup_ok
        for item in images.values():
            if item['tag'] not in preexisting:
                cleanup_ok = remove_image(item['tag'], item['id']) and cleanup_ok
        if dex_id is not None and not dex_preexisting:
            cleanup_ok = remove_image(DEX_IMAGE, dex_id) and cleanup_ok
        result['owned_services_removed'] = cleanup_ok
        if stage.parent != Path(tempfile.gettempdir()).resolve() or not stage.name.startswith('nethub-oidc-'):
            raise Failure('private fixture cleanup path mismatch')
        if cleanup_ok:
            try:
                shutil.rmtree(stage)
            except OSError:
                cleanup_ok = False
        result['private_material_removed'] = cleanup_ok and not stage.exists()
        result['passed'] = result['passed'] and cleanup_ok and successful
        (evidence / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
        if not cleanup_ok:
            # Keep protected bind sources available if Docker cleanup failed.
            # This recovery pointer is deliberately excluded from CI artifacts.
            (evidence / 'private-recovery.json').write_text(json.dumps({'stage': str(stage), 'project': project}))
        publish_evidence(evidence)
        if not cleanup_ok:
            raise Failure('owned SSO cleanup could not be confirmed')
    print('Fresh two-Dex browser/SQL admission and owned-resource cleanup passed with normal TLS verification.')


if __name__ == '__main__':
    try:
        main()
    except (Failure, OSError, ValueError, KeyError) as error:
        # Do not publish subprocess arguments, cookies, codes or private logs.
        print('Two-Dex deployment acceptance failed: ' + (str(error) if isinstance(error, Failure) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
