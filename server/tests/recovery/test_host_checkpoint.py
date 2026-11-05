"""Reject foreign host, unit, image and request input before guest operations."""
import copy
import os
import unittest
from unittest.mock import patch

from database import snapshot_fingerprint
from host_checkpoint import CheckpointError, SourceCheckpoint, valid_capture_input, valid_checkpoint, valid_restore_input
from host_layout import ROLES, RUNNING, STATE_ROOTS, UNITS, VOLUMES
from linux_guest import LinuxGuest
from target_host import ordered_handoff


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


def checkpoint():
    original = expected_source()
    database = [['table', 'devices', 'a' * 64], ['extensions', '', 'fixture extension metadata']]
    return {'version': 1, 'source_head': original['source_head'], 'source_machine_id': original['machine_id'],
            'source_boot_id': original['boot_id'], 'tags': original['tags'],
            'original_service_ids': {name: format(i + 1, '064x') for i, name in enumerate(sorted(RUNNING))},
            'roots': list(STATE_ROOTS), 'unit_hashes': original['unit_hashes'],
            'unit_intent': {unit: 'enabled' if unit.endswith('.timer') else 'static' for unit in UNITS},
            'account_hash': original['account_hash'], 'native_device_id': original['native_device_id'],
            'pending_request_id': original['pending_request_id'], 'database': database,
            'database_fingerprint': snapshot_fingerprint(database), 'original_database_system': '12345678',
            'dump': VOLUMES['database-backups'] + '/nethub-20261105T120000Z-' + 'a' * 16 + '.dump',
            'dump_sha256': 'b' * 64, 'payload': {'sha256': 'c' * 64, 'inventory_sha256': 'd' * 64, 'entries': 100},
            'original_services_and_issuer_stopped': True}


class RestoreAdmission(unittest.TestCase):
    def test_checkpoint_cannot_redirect_paths_skip_writers_or_change_database_content(self):
        original = checkpoint()
        self.assertTrue(valid_checkpoint(original))
        for field, value in [('roots', ['/etc']), ('original_services_and_issuer_stopped', False),
                             ('dump', '/etc/foreign.dump'), ('database_fingerprint', 'e' * 64),
                             ('database', [['table', 'devices', 'different private content']]),
                             ('payload', {'sha256': 'invalid', 'inventory_sha256': 'd' * 64, 'entries': 100}),
                             ('original_service_ids', dict.fromkeys(RUNNING, 'a' * 64)),
                             ('unit_intent', dict.fromkeys(UNITS, 'disabled'))]:
            with self.subTest(field=field):
                self.assertFalse(valid_checkpoint({**original, field: value}))
        self.assertFalse(valid_checkpoint({**original, 'unexpected_root': '/var/lib'}))

    def test_target_identity_and_both_archive_hashes_are_required(self):
        original = {'version': 1, 'machine_id': 'b' * 32, 'boot_id': '44444444-4444-4444-8444-444444444444',
                    'source_head': 'a' * 40, 'checkpoint_sha256': 'b' * 64, 'payload_sha256': 'c' * 64}
        self.assertTrue(valid_restore_input(original))
        for field, value in [('machine_id', '../other'), ('boot_id', 'unknown'), ('source_head', None),
                             ('checkpoint_sha256', 'wrong'), ('payload_sha256', 'wrong'), ('version', True)]:
            with self.subTest(field=field):
                self.assertFalse(valid_restore_input({**original, field: value}))

    def test_handoff_requires_actual_terminal_source_and_chronological_target_launch(self):
        class Process:
            def __init__(self, status):
                self.status = status
            def poll(self):
                return self.status
        source, target = object.__new__(LinuxGuest), object.__new__(LinuxGuest)
        source.process, target.process = Process(0), Process(None)
        source.stopped_monotonic, target.started_monotonic = 10.0, 11.0
        self.assertTrue(ordered_handoff(source, target))
        for status, stopped, started in ((None, 10.0, 11.0), (0, None, 11.0),
                                         (0, 12.0, 11.0), (0, float('nan'), 11.0),
                                         (0, 10.0, float('inf')), (0, True, 11.0)):
            source.process, source.stopped_monotonic, target.started_monotonic = Process(status), stopped, started
            with self.subTest(status=status, stopped=stopped, started=started):
                self.assertFalse(ordered_handoff(source, target))

    def test_repeated_owned_cleanup_preserves_the_first_observed_source_stop(self):
        class Reaped:
            def poll(self):
                return 0
        source = object.__new__(LinuxGuest)
        source.process, source.log, source.stopped_monotonic = Reaped(), None, None
        with patch('linux_guest.time.monotonic', return_value=10.0) as observed:
            source.__exit__(None, None, None)
            source.__exit__(None, None, None)
            self.assertEqual(source.stopped_monotonic, 10.0)
            self.assertEqual(observed.call_count, 1)


if __name__ == '__main__':
    unittest.main()
