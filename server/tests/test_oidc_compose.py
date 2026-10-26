"""Check SSO orchestration ownership and refusal paths without Docker."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('oidc_compose', Path(__file__).with_name('oidc-compose.py'))
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)


class OIDCOwnershipBoundaries(unittest.TestCase):
    def archive(self, directory):
        raw = b'owned opaque image archive'
        (directory / 'images.tar.gz').write_bytes(raw)
        (directory / 'SHA256SUMS').write_text(hashlib.sha256(raw).hexdigest() + '  images.tar.gz\n')
        images = {name: {'tag': 'nethub-stack-test:tmp-owned-' + name, 'id': 'sha256:' + str(index) * 64,
                         'platform': 'linux/amd64', 'diff_ids': ['sha256:' + 'a' * 64]}
                  for index, name in enumerate(('runtime', 'postgres', 'caddy', 'frps'), 1)}
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
                        self.assertEqual(len(calls), 4)
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


if __name__ == '__main__':
    unittest.main()
