"""Exercise both input staging paths without launching a host or checkpoint."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from host_layout import TRANSFER
from linux_guest import RecoveryError
from source_host import DeploymentHost, SourceHost
from target_host import TargetHost
from test_host_checkpoint import checkpoint, expected_source


class InputReady(Exception):
    """Stop before any guest checkpoint operation can execute."""


class CheckpointInputStaging(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.received = self.root / 'received'
        self.received.mkdir()
        self.installed = None

    def send(self, source, name):
        with (self.received / name).open('xb') as output:
            output.write(Path(source).read_bytes())
        return TRANSFER + '/' + name

    def remote(self, arguments, _label, **_options):
        if arguments[0] == 'install':
            self.assertEqual(arguments[:7], ['install', '-o', 'root', '-g', 'root', '-m', '0600'])
            source, target = [self.received / Path(name).name for name in arguments[-2:]]
            self.assertNotEqual(source, target)
            if os.name == 'posix':
                subprocess.run(['install', '-m', '0600', str(source), str(target)],
                               check=True, capture_output=True, timeout=10)
            else:
                shutil.copyfile(source, target)
            self.installed = json.loads(target.read_bytes())
            return b''
        if arguments[0] == 'sha256sum':
            return hashlib.sha256((self.received / Path(arguments[1]).name).read_bytes()).hexdigest().encode()
        self.assertEqual(arguments[:2], ['python3', TRANSFER + '/host_checkpoint.py'])
        self.assertIn(arguments[2], ('capture', 'restore'))
        self.assertTrue((self.received / (arguments[2] + '-input.json')).is_file())
        raise InputReady()

    def host(self, kind):
        host = object.__new__(kind)
        host.work = self.root / 'work'
        host.work.mkdir()
        host.guest = SimpleNamespace(send=self.send)
        host.remote = self.remote
        host.send_module = Mock()
        host.command = Mock(return_value=b'fixture unit')
        host.head = 'a' * 40
        return host

    def test_same_path_is_refused_before_a_transfer_or_local_file_is_created(self):
        host = self.host(DeploymentHost)
        host.guest.send = Mock(side_effect=AssertionError('Transfer must not start'))
        for name in ('capture-input.json', 'restore-input.json'):
            with self.subTest(name=name), self.assertRaises(RecoveryError):
                host.install_file(b'private fixture', name, TRANSFER + '/' + name, '0600')
        host.guest.send.assert_not_called()
        self.assertEqual(list(host.work.iterdir()), [])

    def test_source_capture_installs_exact_private_input_from_a_distinct_staging_file(self):
        host = self.host(SourceHost)
        expected = expected_source()
        host.stack_started = host.issuer_configured = True
        host.transfer_module = 'already transferred fixture'
        host.guest.identity = {'machine_id': expected['machine_id'], 'boot_id': expected['boot_id']}
        host.tags, host.account_hash = expected['tags'], expected['account_hash']
        with self.assertRaises(InputReady):
            host.capture_checkpoint(expected['native_device_id'], expected['pending_request_id'])
        expected['unit_hashes'] = dict.fromkeys(expected['unit_hashes'], hashlib.sha256(b'fixture unit').hexdigest())
        self.assertEqual(self.installed, expected)
        self.assertFalse(getattr(host, 'checkpoint_created', False))

    def test_target_restore_installs_exact_hash_bound_input_from_a_distinct_staging_file(self):
        host = self.host(TargetHost)
        metadata, payload = self.root / 'checkpoint.json', self.root / 'current-files.tar'
        payload.write_bytes(b'private payload fixture')
        value = checkpoint()
        value['payload']['sha256'] = hashlib.sha256(payload.read_bytes()).hexdigest()
        metadata.write_text(json.dumps(value), encoding='utf-8')
        host.source = SimpleNamespace(identity={'machine_id': value['source_machine_id'],
                                                'boot_id': value['source_boot_id']})
        host.guest.identity = {'machine_id': 'b' * 32, 'boot_id': '44444444-4444-4444-8444-444444444444'}
        host.restored = host.host_prepared = False
        host.prepare_images = Mock(return_value={'fixture': True})
        with patch('target_host.ordered_handoff', return_value=True), self.assertRaises(InputReady):
            host.restore(Path('unused-images'), value['tags'], metadata, payload)
        self.assertEqual(self.installed, {'version': 1, **host.guest.identity, 'source_head': host.head,
            'checkpoint_sha256': hashlib.sha256(metadata.read_bytes()).hexdigest(),
            'payload_sha256': hashlib.sha256(payload.read_bytes()).hexdigest()})
        self.assertFalse(host.restored)


if __name__ == '__main__':
    unittest.main()
