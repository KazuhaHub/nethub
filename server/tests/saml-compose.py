"""Run an independent official SAML IdP against a fresh production deployment."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
IDP_IMAGE = 'quay.io/keycloak/keycloak:26.8.1@sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b'
spec = importlib.util.spec_from_file_location('owned_sso', ROOT / 'server/tests/oidc-compose.py')
owned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owned)
Failure = owned.Failure
invoke = owned.invoke
docker_json = owned.docker_json


def realm_import(password):
    if not re.fullmatch('[a-f0-9]{64}', password):
        raise Failure('unexpected disposable user credential format')
    return {
        'realm': 'nethub-saml', 'enabled': True, 'sslRequired': 'external',
        'registrationAllowed': False, 'loginWithEmailAllowed': False,
        'resetPasswordAllowed': False, 'verifyEmail': False,
        'users': [
            {'username': username, 'enabled': True, 'emailVerified': verified,
             'email': email, 'firstName': 'Acceptance', 'lastName': username,
             'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
            for username, email, verified in [
                ('alice', 'alice@example.com', False),
                ('bob', 'bob@example.com', True),
                ('mailbox', 'compose-admin@example.com', True),
            ]
        ],
    }


def idp_service(address, realm_file, admin_password):
    return {
        'image': IDP_IMAGE,
        'command': ['start-dev', '--hostname=https://saml.test', '--proxy-headers=xforwarded',
                    '--http-enabled=true', '--import-realm', '--log-level=ERROR'],
        'user': '1000:0', 'cap_drop': ['ALL'],
        'security_opt': ['no-new-privileges:true'], 'pids_limit': 256, 'mem_limit': '1024m',
        # Development augmentation writes only to this owned container overlay.
        # It is an isolated disposable IdP, not a production deployment example.
        'environment': {'KC_BOOTSTRAP_ADMIN_USERNAME': 'fixture-admin',
                        'KC_BOOTSTRAP_ADMIN_PASSWORD': admin_password,
                        'JAVA_OPTS_KC_HEAP': '-Xms128m -Xmx384m',
                        'JAVA_OPTS_APPEND': '-XX:ActiveProcessorCount=2 -XX:MaxMetaspaceSize=256m'},
        'tmpfs': ['/tmp:rw,nosuid,nodev,size=128m,mode=1777'],
        'volumes': [{'type': 'bind', 'source': str(realm_file),
                     'target': '/opt/keycloak/data/import/nethub-saml-realm.json', 'read_only': True}],
        'networks': {'edge': {'ipv4_address': address}},
        'logging': {'driver': 'json-file', 'options': {'max-size': '5m', 'max-file': '2'}},
    }


def publish_evidence(directory):
    uid, gid = int(os.environ.get('SUDO_UID', '0')), int(os.environ.get('SUDO_GID', '0'))
    for name in ('keycloak-alice-login.png', 'keycloak-bob-login.png', 'results.json'):
        path = directory / name
        if path.exists():
            if not path.is_file() or path.is_symlink():
                raise Failure('unsafe SAML evidence path')
            os.chown(path, uid, gid)
    os.chown(directory, uid, gid)


def main():
    if sys.platform != 'linux' or os.geteuid() != 0 or len(sys.argv) != 3:
        raise Failure('Linux root, accepted image archive and fresh evidence directory required')
    os.umask(0o077)
    version = docker_json(['version', '--format', '{{json .Server.Version}}'], 'Docker readiness')
    if int(version.split('.')[0]) < 28:
        raise Failure('Docker 28 or newer required for loopback isolation')
    evidence = Path(sys.argv[2]).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    stage = Path(tempfile.mkdtemp(prefix='nethub-saml-')).resolve()
    project = 'nethub-saml-' + os.urandom(8).hex()
    helper_image = project + ':helper'
    helper_id = holder_id = idp_id = None
    images, preexisting = {}, set()
    compose_file = stage / 'compose.json'
    browser_started = successful = False
    idp_preexisting = invoke(['docker', 'image', 'inspect', IDP_IMAGE], 'IdP inventory', check=False).returncode == 0
    result = {'passed': False, 'scope': 'fresh production deployment and official Keycloak SAML IdP',
              'full_W6_acceptance_claimed': False}

    def compose(*arguments, timeout=60, input=None, check=True):
        reply = invoke(['docker', 'compose', '-p', project, '-f', str(compose_file), *arguments],
                       'owned SAML Compose ' + arguments[0], timeout=timeout, input=input, check=False)
        if check and reply.returncode:
            result['failed_compose_operation'] = arguments[0]
            if not browser_started and arguments[0] in ('up', 'run', 'ps'):
                result['startup_diagnostic'] = owned.startup_diagnostic(stage, reply.stderr)
            raise Failure('owned SAML Compose ' + arguments[0] + ' failed')
        return reply

    try:
        images, preexisting = owned.archive_images(sys.argv[1])
        invoke(['docker', 'load', '-i', str(Path(sys.argv[1]).resolve() / 'images.tar.gz')], 'verified image load', timeout=90)
        owned.verify_loaded_images(images)
        if invoke(['docker', 'image', 'inspect', helper_image], 'prior fixture image inventory', check=False).returncode == 0:
            raise Failure('fixture image reference already exists')
        build = invoke(['docker', 'build', '--target', 'oidc-acceptance', '-f', str(ROOT / 'deploy/Dockerfile'),
                        '-t', helper_image, str(ROOT)], 'SAML TLS fixture build', timeout=240,
                       log=stage / 'helper-build.log', check=False)
        if build.returncode:
            result['failed_preparation'] = 'fixture_build'
            result['startup_diagnostic'] = owned.startup_diagnostic(stage, build.stdout + build.stderr)
            raise Failure('SAML TLS fixture build failed')
        helper_id = docker_json(['image', 'inspect', helper_image], 'fixture image identity')[0]['Id']
        holder_id = invoke(['docker', 'create', '--network', 'none', '--label', 'org.nethub.test=' + project,
                            helper_image, '/oidcfixture'], 'fixture extraction container').stdout.decode().strip()
        helper = stage / 'oidcfixture'
        invoke(['docker', 'cp', holder_id + ':/oidcfixture', str(helper)], 'fixture binary extraction')
        invoke(['docker', 'rm', holder_id], 'fixture extraction cleanup')
        holder_id = None
        helper.chmod(0o700)
        fixture = stage / 'fixture'
        invoke([str(helper), str(fixture)], 'fresh SAML HTTPS material')
        credentials = json.loads((fixture / 'credentials.json').read_text())
        realm_file = fixture / 'nethub-saml-realm.json'
        realm_file.write_text(json.dumps(realm_import(credentials['password'])))
        realm_file.chmod(0o600)
        os.chown(realm_file, 1000, 0)
        invoke(['docker', 'pull', '--platform', 'linux/amd64', IDP_IMAGE], 'pinned official IdP pull',
               timeout=150, log=stage / 'idp-pull.log')
        idp = docker_json(['image', 'inspect', IDP_IMAGE], 'IdP image identity')[0]
        idp_id = idp['Id']
        if idp['Os'] != 'linux' or idp['Architecture'] != 'amd64' or not any(value.endswith('@' + IDP_IMAGE.split('@')[1]) for value in idp['RepoDigests']):
            raise Failure('IdP registry/platform identity mismatch')
        runtime = images['runtime']['tag']
        invoke(['docker', 'run', '--rm', '-i', '--network', 'none', '--user', '0', '-v', str(ROOT) + ':' + str(ROOT) + ':ro',
                '-v', str(stage) + ':' + str(stage), runtime, 'init', '--offline', '--source-directory', str(ROOT),
                '--directory', str(stage / 'deployment'), '--backup-directory', str(stage / 'backup'),
                '--console-host', 'console.example.com', '--device-domain', 'router.example.com',
                '--oidc-private-host', 'saml.test'], 'fresh SAML deployment initialization', timeout=90,
               input=b'I HAVE VERIFIED THE NETHUB SECRET BACKUP\n', log=stage / 'init.log')
        deployment = stage / 'deployment'
        raw = invoke(['docker', 'compose', '-p', project, '-f', str(deployment / 'docker-compose.yml'),
                      '-f', str(deployment / 'docker-compose.override.yml'), '--profile', 'bootstrap',
                      'config', '--format', 'json'], 'SAML Compose normalization').stdout
        config = json.loads(raw)
        services = config['services']
        for service in ('migrate', 'nethub-web', 'nethub-authz', 'admin-bootstrap'):
            services[service]['image'] = runtime
        for service in ('postgres', 'caddy', 'frps', 'backup'):
            services[service]['image'] = images[service]['tag']
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        caddy = services['caddy']
        caddy['ports'] = [{'host_ip': '127.0.0.1', 'published': str(port), 'target': 443, 'protocol': 'tcp'}]
        caddy['networks']['edge']['aliases'] = ['saml.test']
        source = (ROOT / 'deploy/Caddyfile').read_text()
        if source.count('{$NETHUB_CONSOLE_HOST} {') != 1:
            raise Failure('console TLS route template changed')
        source = source.replace('{$NETHUB_CONSOLE_HOST} {', '''https://console.example.com {
    tls /fixture/origin.crt /fixture/origin.key
    @captureSAML {
        path /api/v1/console/saml/keycloak/callback
        header X-Nethub-Test-Capture 1
    }
    respond @captureSAML "SAML callback captured" 200''', 1)
        source += '\nhttps://saml.test {\n    tls /fixture/origin.crt /fixture/origin.key\n    reverse_proxy saml-idp:8080\n}\n'
        caddy_file = stage / 'Caddyfile'
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
        address = owned.dex_addresses(config)['one']
        services['saml-idp'] = idp_service(address, realm_file, credentials['clients']['one'])
        owned.require_empty_namespace(config, project)
        for host, listening_port in [('0.0.0.0', 7000), ('0.0.0.0', 8443), ('127.0.0.1', 7500), ('127.0.0.1', 9000)]:
            with socket.socket() as listener:
                listener.bind((host, listening_port))
        compose_file.write_text(json.dumps(config))
        compose('up', '-d', '--no-build', '--wait', '--wait-timeout', '150', timeout=180)
        admin_password = stage / 'admin-password'
        admin_password.write_text(os.urandom(32).hex() + '\n')
        compose('run', '--rm', '-T', 'admin-bootstrap', '--email', 'compose-admin@example.com', '--password-stdin',
                timeout=90, input=admin_password.read_bytes())
        for host, path in [('console.example.com', '/'), ('saml.test', '/realms/nethub-saml/protocol/saml/descriptor')]:
            for attempt in range(45):
                reply = invoke(['curl', '--fail', '--silent', '--show-error', '--noproxy', '*', '--cacert', str(fixture / 'root.crt'),
                                '--connect-to', host + ':443:127.0.0.1:' + str(port), '--max-time', '3', 'https://' + host + path],
                               'SAML HTTPS readiness', timeout=5, check=False)
                if reply.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise Failure('SAML origin did not become ready with normal TLS verification')
        browser_home = stage / 'browser-home'
        database = browser_home / '.local/share/pki/nssdb'
        database.mkdir(parents=True)
        invoke(['certutil', '-N', '-d', 'sql:' + str(database), '--empty-password'], 'isolated browser trust initialization')
        invoke(['certutil', '-A', '-d', 'sql:' + str(database), '-n', project, '-t', 'C,,', '-i', str(fixture / 'root.crt')], 'isolated browser test-CA import')
        database_container = compose('ps', '-q', 'postgres').stdout.decode().strip()
        web_container = compose('ps', '-q', 'nethub-web').stdout.decode().strip()
        browser_evidence = stage / 'browser'
        browser_started = True
        reply = invoke([os.environ.get('NETHUB_NODE_BINARY', 'node'), str(ROOT / 'server/web/tests/saml-deployment.mjs'),
                        str(port), str(admin_password), str(fixture), str(browser_home), str(browser_evidence), database_container, web_container],
                       'real Keycloak SAML browser admission', timeout=240, log=stage / 'browser-private.log', check=False)
        if reply.returncode:
            failed = browser_evidence / 'results.json'
            if failed.exists():
                failure = json.loads(failed.read_text())
                if re.fullmatch('[a-z_]{1,64}', failure.get('phase', '')):
                    result['failed_phase'] = failure['phase']
                    result.update(owned.browser_diagnostic(failure))
            raise Failure('real Keycloak browser admission failed')
        print(reply.stdout.decode(), end='')
        result = json.loads((browser_evidence / 'results.json').read_text())
        private_values = json.loads((browser_evidence / 'privacy-values.json').read_text())
        logs = compose('logs', '--no-color').stdout.decode(errors='replace')
        if any(value in logs for value in private_values):
            raise Failure('authentication material appeared in deployed service logs')
        result['all_service_logs_checked_for_secret_absence'] = True
        result['idp_image'] = IDP_IMAGE
        result['idp_image_id'] = idp_id
        result['deployed_images'] = {name: item['id'] for name, item in images.items()}
        for name in ('keycloak-alice-login.png', 'keycloak-bob-login.png'):
            shutil.copyfile(browser_evidence / name, evidence / name)
        successful = True
    finally:
        cleanup_ok = True
        if holder_id is not None:
            cleanup_ok = invoke(['docker', 'rm', '-f', holder_id], 'fixture holder cleanup', check=False).returncode == 0
        if compose_file.exists():
            cleanup_ok = compose('down', '-v', '--remove-orphans', timeout=90, check=False).returncode == 0 and cleanup_ok
            for kind, arguments in [('containers', ['ps', '-aq']), ('volumes', ['volume', 'ls', '-q']), ('networks', ['network', 'ls', '-q'])]:
                remaining = invoke(['docker', *arguments, '--filter', 'label=com.docker.compose.project=' + project], 'owned SAML ' + kind + ' cleanup', check=False)
                cleanup_ok = cleanup_ok and remaining.returncode == 0 and not remaining.stdout.strip()
        if helper_id is not None:
            cleanup_ok = owned.remove_image(helper_image, helper_id) and cleanup_ok
        for item in images.values():
            if item['tag'] not in preexisting:
                cleanup_ok = owned.remove_image(item['tag'], item['id']) and cleanup_ok
        if idp_id is not None and not idp_preexisting:
            cleanup_ok = owned.remove_image(IDP_IMAGE, idp_id) and cleanup_ok
        result['owned_services_removed'] = cleanup_ok
        if stage.parent != Path(tempfile.gettempdir()).resolve() or not stage.name.startswith('nethub-saml-'):
            raise Failure('private SAML cleanup path mismatch')
        if cleanup_ok:
            try:
                shutil.rmtree(stage)
            except OSError:
                cleanup_ok = False
        result['private_material_removed'] = cleanup_ok and not stage.exists()
        result['passed'] = result['passed'] and cleanup_ok and successful
        (evidence / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
        if not cleanup_ok:
            (evidence / 'private-recovery.json').write_text(json.dumps({'stage': str(stage), 'project': project}))
        publish_evidence(evidence)
        if not cleanup_ok:
            raise Failure('owned SAML cleanup could not be confirmed')
    print('Fresh official Keycloak SAML browser/SQL admission and owned cleanup passed with normal TLS verification.')


if __name__ == '__main__':
    try:
        main()
    except (Failure, OSError, ValueError, KeyError) as error:
        print('Keycloak SAML deployment acceptance failed: ' + (str(error) if isinstance(error, Failure) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
