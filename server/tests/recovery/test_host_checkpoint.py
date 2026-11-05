"""Reject foreign host, unit, image and request input before guest operations."""
import copy
import os
import unittest

from host_checkpoint import CheckpointError, SourceCheckpoint, valid_capture_input
from host_layout import ROLES, UNITS


def expected_source():
    return {'version': 1, 'machine_id': 'a' * 32,
            'boot_id': '11111111-1111-4111-8111-111111111111', 'source_head': 'a' * 40,
            'tags': {role: 'owned/' + role + ':source' for role in ROLES},
            'unit_hashes': {unit: 'a' * 64 for unit in UNITS}, 'account_hash': 'b' * 64,
            'native_device_id': '22222222-2222-4222-8222-222222222222',
            'pending_request_id': '33333333-3333-4333-8333-333333333333'}


class CaptureInputAdmission(unittest.TestCase):
    def test_only_exact_canonical_owned_input_is_admitted(self):
        expected = expected_source()
        self.assertTrue(valid_capture_input(expected))
        for key, value in [('version', True), ('version', 2), ('machine_id', '../other-host'),
                           ('boot_id', 'private-host'), ('source_head', 'a' * 39),
                           ('account_hash', 'not-an-identity'), ('native_device_id', "'; SELECT 1;"),
                           ('pending_request_id', '{33333333-3333-4333-8333-333333333333}')]:
            changed = {**expected, key: value}
            with self.subTest(key=key, value=value):
                self.assertFalse(valid_capture_input(changed))
        self.assertFalse(valid_capture_input({**expected, 'roots': ['/etc']}))
        self.assertFalse(valid_capture_input({key: value for key, value in expected.items() if key != 'account_hash'}))

    def test_units_and_images_cannot_select_an_unrelated_privileged_resource(self):
        expected = expected_source()
        for field, value in [('unit_hashes', {**expected['unit_hashes'], 'docker.service': 'c' * 64}),
                             ('unit_hashes', {unit: 'invalid' for unit in UNITS}),
                             ('tags', {**expected['tags'], 'runtime': '--privileged'}),
                             ('tags', {**expected['tags'], 'runtime': expected['tags']['backup']})]:
            with self.subTest(field=field):
                self.assertFalse(valid_capture_input({**expected, field: value}))
        before = copy.deepcopy(expected)
        self.assertTrue(valid_capture_input(expected))
        self.assertEqual(expected, before)

    def test_bad_container_types_are_refused_without_operating_a_host(self):
        for value in (None, [], {}, {'version': 1}, 'private input'):
            self.assertFalse(valid_capture_input(value))
        if os.name != 'posix':
            with self.assertRaises(CheckpointError):
                SourceCheckpoint(expected_source())


if __name__ == '__main__':
    unittest.main()
