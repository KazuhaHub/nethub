"""Check SSO orchestration ownership and refusal paths without Docker."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('oidc_compose', Path(__file__).with_name('oidc-compose.py'))
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)


class OIDCOwnershipBoundaries(unittest.TestCase):
    def test_docker_names_do_not_inherit_unsafe_temporary_directory_suffixes(self):
        with patch.object(suite.os, 'urandom', return_value=bytes(range(8))):
            project = suite.docker_project()
        self.assertRegex(project, r'^nethub-oidc-[a-f0-9]{16}$')
        self.assertEqual(project, 'nethub-oidc-0001020304050607')

    def test_provider_diagnostics_publish_only_fixed_categories_and_scalar_checks(self):
        safe = {'dns_resolved': True, 'metadata_issuer_matches': False, 'discovery_status': 200,
                'console_discovery_ok': False, 'console_error': 'console_discovery', 'network_error': 'none'}
        self.assertEqual(suite.provider_diagnostic(dict(safe, issuer='private-url', token='private-token')), safe)
        for unsafe in ('private-secret', ['private-secret'], {'error': 'private-secret'}, None, 100001):
            self.assertEqual(suite.provider_diagnostic({name: unsafe for name in safe}), {})

    def test_browser_diagnostics_never_publish_assertion_values_or_error_text(self):
        safe = {'failure_line': 472, 'assertion_actual': False, 'assertion_expected': 201,
                'provider_status': 422, 'provider_error': 'oidc_discovery_failed',
                'callback_binding_cookie_sent': True, 'callback_has_scope': False,
                'last_sso_reason': 'admission_denied', 'flow_consumed_count': 1}
        self.assertEqual(suite.browser_diagnostic(dict(safe, stack='private-stack', message='private-message')), safe)
        for unsafe in ('private-secret', ['private-secret'], {'message': 'private-secret'}, None, 100001, -100001):
            self.assertEqual(suite.browser_diagnostic({name: unsafe for name in safe}), {})
        self.assertEqual(suite.browser_diagnostic({'failure_line': True, 'provider_status': False}), {})

    def test_dex_addresses_do_not_race_reserved_deployment_addresses(self):
        for subnet, gateway in [('172.30.87.0/24', '172.30.87.1'), ('192.168.19.0/29', '192.168.19.1')]:
            prefix = gateway.rsplit('.', 1)[0]
            config = {'networks': {'edge': {'ipam': {'config': [{'subnet': subnet, 'gateway': gateway}]}}},
                      'services': {name: {'networks': {'edge': {'ipv4_address': prefix + '.' + str(index)}}}
                                   for index, name in enumerate(('caddy', 'web', 'authz'), 2)}}
            before = json.dumps(config, sort_keys=True)
            self.assertEqual(suite.dex_addresses(config), {'one': prefix + '.5', 'two': prefix + '.6'})
            self.assertEqual(json.dumps(config, sort_keys=True), before)
            config['services']['extra'] = {'networks': {'edge': {'ipv4_address': prefix + '.5'}}}
            if subnet.endswith('/29'):
                with self.assertRaises(suite.Failure):
                    suite.dex_addresses(config)
            else:
                self.assertEqual(suite.dex_addresses(config), {'one': prefix + '.6', 'two': prefix + '.7'})

    def archive(self, directory):
        raw = b'owned opaque image archive'
        (directory / 'images.tar.gz').write_bytes(raw)
        (directory / 'SHA256SUMS').write_text(hashlib.sha256(raw).hexdigest() + '  images.tar.gz\n')
        images = {name: {'tag': 'nethub-stack-test:tmp-owned-' + name, 'id': 'sha256:' + str(index) * 64,
                         'platform': 'linux/amd64', 'diff_ids': ['sha256:' + 'a' * 64]}
                  for index, name in enumerate(('runtime', 'postgres', 'caddy', 'frps', 'backup'), 1)}
        (directory / 'images.json').write_text(json.dumps(images))
        return images

    def test_archive_refuses_tampering_unrelated_tags_and_retagging_before_load(self):
        for mode in ('valid', 'checksum', 'unrelated', 'conflicting'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                images = self.archive(directory)
                if mode == 'checksum':
                    (directory / 'images.tar.gz').write_bytes(b'changed')
                if mode == 'unrelated':
                    images['runtime']['tag'] = 'production:current'
                    (directory / 'images.json').write_text(json.dumps(images))
                calls = []

                def fake(arguments, _label, **_options):
                    calls.append(arguments)
                    self.assertEqual(arguments[:3], ['docker', 'image', 'inspect'])
                    if mode == 'conflicting':
                        return SimpleNamespace(returncode=0, stdout=json.dumps([{'Id': 'sha256:' + 'f' * 64}]).encode())
                    return SimpleNamespace(returncode=1, stdout=b'')

                with patch.object(suite, 'invoke', side_effect=fake):
                    if mode == 'valid':
                        self.assertEqual(suite.archive_images(directory), (images, set()))
                        self.assertEqual(len(calls), 5)
                    else:
                        with self.assertRaises(suite.Failure):
                            suite.archive_images(directory)
                if mode in ('checksum', 'unrelated'):
                    self.assertEqual(calls, [])

    def test_namespace_refuses_existing_or_external_resources_without_mutations(self):
        project = 'nethub-oidc-owned'
        for mode in ('valid', 'external', 'foreign_name', 'container', 'network', 'volume'):
            with self.subTest(mode=mode):
                config = {'networks': {'edge': {'name': project + '_edge'}}, 'volumes': {'db': {'name': project + '_db'}}}
                if mode == 'external':
                    config['networks']['edge']['external'] = True
                if mode == 'foreign_name':
                    config['volumes']['db']['name'] = 'existing-production-data'
                calls = []

                def fake(arguments, _label, **_options):
                    calls.append(arguments)
                    if arguments[1] == 'ps':
                        return SimpleNamespace(returncode=0, stdout=b'existing-container' if mode == 'container' else b'')
                    self.assertIn(arguments[1], ('network', 'volume'))
                    self.assertEqual(arguments[2], 'inspect')
                    return SimpleNamespace(returncode=0 if arguments[1] == mode else 1, stdout=b'')

                with patch.object(suite, 'invoke', side_effect=fake):
                    if mode == 'valid':
                        suite.require_empty_namespace(config, project)
                    else:
                        with self.assertRaises(suite.Failure):
                            suite.require_empty_namespace(config, project)
                if mode in ('external', 'foreign_name'):
                    self.assertEqual(calls, [])

    def test_cleanup_does_not_delete_a_retargeted_image(self):
        calls = []

        def fake(arguments, _label, **_options):
            calls.append(arguments)
            return SimpleNamespace(returncode=0, stdout=json.dumps([{'Id': 'sha256:' + 'b' * 64}]).encode())

        with patch.object(suite, 'invoke', side_effect=fake):
            self.assertFalse(suite.remove_image('nethub-stack-test:tmp-owned', 'sha256:' + 'a' * 64))
        self.assertEqual(calls, [['docker', 'image', 'inspect', 'nethub-stack-test:tmp-owned']])

    def test_command_deadline_has_no_argument_or_output_leak(self):
        with self.assertRaisesRegex(suite.Failure, '^isolated command deadline exceeded$'):
            suite.invoke([sys.executable, '-c', 'import time;time.sleep(5)', 'private-fixture-argument'], 'isolated command', timeout=0.05)

    def test_startup_diagnostic_masks_fixture_and_deployment_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            fixture = stage / 'fixture'
            fixture.mkdir()
            password, client, stored_hash, owner_password = ('public-fixture-password-value', 'public-fixture-client-value', 'public-fixture-bcrypt-value', 'public-fixture-owner-value')
            (fixture / 'credentials.json').write_text(json.dumps({'password': password, 'clients': {'one': client}}))
            (fixture / 'dex-one.json').write_text(json.dumps({'staticPasswords': [{'hash': stored_hash}]}))
            secrets = stage / 'deployment/secrets/web'
            secrets.mkdir(parents=True)
            (secrets / 'pg_nethub_web').write_text(owner_password + '\n')
            raw = f'Invalid option in {stage}: {password} {client} {stored_hash} {owner_password}'.encode()
            diagnostic = suite.startup_diagnostic(stage, raw)
            self.assertIn('Invalid option in [owned stage]', diagnostic)
            self.assertEqual(diagnostic.count('[redacted]'), 4)
            for value in (password, client, stored_hash, owner_password):
                self.assertNotIn(value, diagnostic)

    def test_only_safe_evidence_is_published_to_the_runner(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            public = ('dex-one-login.png', 'dex-two-login.png', 'results.json')
            for name in (*public, 'privacy-values.json', 'private-recovery.json'):
                (directory / name).write_text('public fixture placeholder')
            calls = []
            with patch.dict(suite.os.environ, {'SUDO_UID': '1001', 'SUDO_GID': '1002'}), patch.object(suite.os, 'chown', side_effect=lambda path, uid, gid: calls.append((path, uid, gid)), create=True):
                suite.publish_evidence(directory)
            self.assertEqual(calls, [(directory / name, 1001, 1002) for name in public] + [(directory, 1001, 1002)])


if __name__ == '__main__':
    unittest.main()
