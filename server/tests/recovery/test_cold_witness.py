"""Refuse foreign resource deletion and retain the guard if cleanup fails."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import cold_witness as witness


class WitnessOwnership(unittest.TestCase):
    def test_operation_names_and_state_cannot_select_foreign_resources(self):
        nonce = 'a' * 16
        self.assertEqual(witness.unit_names(nonce), ('nethub-cold-witness-' + nonce,
                                                    'nethub-cold-witness-guard-' + nonce))
        for value in (None, '', 'a' * 15, 'a' * 17, '../unrelated', 'a' * 15 + '\n'):
            with self.subTest(value=value), self.assertRaises(witness.WitnessError):
                witness.unit_names(value)
        original = {'version': 1, 'nonce': nonce, 'image_id': 'sha256:' + 'b' * 64, 'binary_sha256': 'c' * 64}
        self.assertTrue(witness.valid_state(original, nonce))
        for key, value in (('version', True), ('nonce', 'd' * 16), ('image_id', '--all'),
                           ('binary_sha256', 'unknown')):
            self.assertFalse(witness.valid_state({**original, key: value}, nonce))
        self.assertFalse(witness.valid_state({**original, 'extra': True}, nonce))

    def test_only_same_label_image_and_closed_private_resource_binding_can_be_removed(self):
        nonce, image = 'a' * 16, 'sha256:' + 'b' * 64
        container = {'Id': 'c' * 64, 'Config': {'Labels': {'org.nethub.guiacme-test': nonce}},
                     'Image': image, 'HostConfig': {'ReadonlyRootfs': True, 'PortBindings': {}}}
        network = {'Id': 'd' * 64, 'Labels': {'org.nethub.guiacme-test': nonce},
                   'Internal': True, 'Driver': 'bridge', 'Containers': {}}
        self.assertTrue(witness.owned_resource(container, 'container', nonce, image))
        self.assertTrue(witness.owned_resource(network, 'network', nonce, image))
        for kind, original, key, value in (
                ('container', container, 'Id', '--all'), ('container', container, 'Image', 'sha256:' + 'e' * 64),
                ('container', container, 'Config', {'Labels': {'org.nethub.guiacme-test': 'f' * 16}}),
                ('container', container, 'HostConfig', {'ReadonlyRootfs': False}),
                ('container', container, 'HostConfig', {'ReadonlyRootfs': True, 'PortBindings': {'443/tcp': [{}]}}),
                ('network', network, 'Internal', False), ('network', network, 'Driver', 'host'),
                ('network', network, 'Containers', {'unrelated': {}}), ('network', network, 'Labels', {})):
            changed = {**copy.deepcopy(original), key: value}
            with self.subTest(kind=kind, field=key):
                self.assertFalse(witness.owned_resource(changed, kind, nonce, image))
        for value in (None, {}, [], {'Id': None}):
            self.assertFalse(witness.owned_resource(value, 'container', nonce, image))

    def test_failed_owned_cleanup_never_disarms_independent_guard(self):
        instance = witness.ColdWitness('unexecuted.test', 'abcdefgh.devices.example.test', 18441)
        with tempfile.TemporaryDirectory() as temporary:
            instance.control = Path(temporary).resolve()
            (instance.control / 'state.json').write_text('fixture')
            with patch.object(witness, 'cleanup', side_effect=witness.WitnessError('fixture refusal')), \
                    patch.object(witness, 'command') as command:
                with self.assertRaises(witness.WitnessError):
                    instance.__exit__(None, None, None)
                command.assert_not_called()

    def test_unowned_platform_is_refused_before_executable_or_host_operations(self):
        if sys.platform != 'linux' or os.geteuid() != 0:
            with self.assertRaises(witness.WitnessError):
                witness.ColdWitness('/unrelated/path', 'abcdefgh.devices.example.test', 18441).__enter__()


if __name__ == '__main__':
    unittest.main()
