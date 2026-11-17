"""Refuse arbitrary public fields and weakened success/cleanup projections."""
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from cold_evidence import validate_cleanup, validate_operation
from cold_operation import PROOFS, TIMINGS, failure
from linux_guest import RecoveryTimeout, invoke
from guest import Guest, GuestError


class ColdEvidenceAdmission(unittest.TestCase):
    def test_original_native_ssh_failure_survives_the_closed_projection(self):
        head = 'a' * 40
        for stdout, stderr, expected in (
                (b'private child output', b'Connection timed out: private peer', 'guest_ssh_connect_timeout'),
                (b'private child output', b'Permission denied: private key', 'guest_ssh_authentication'),
                (json.dumps({'success': False, 'fixture_phase': 'native_bound_key'}).encode(),
                 b'private child output', 'fixture_native_bound_key'),
                (json.dumps({'success': False, 'fixture_phase': 'trust_store_regeneration',
                             'fixture_context': {'kind': 'Error', 'source': 'system', 'line': 819}}).encode(),
                 b'', 'fixture_trust_store_regeneration_Error_system_819')):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                guest = Guest.__new__(Guest)
                guest.directory, guest.ssh_port = Path(directory), 2222
                response = subprocess.CompletedProcess(['private command'], 1, stdout, stderr)
                with patch('guest.subprocess.run', return_value=response) as command:
                    try:
                        guest.ssh('private command', 'private operation')
                    except GuestError as error:
                        value = failure(error, head, 'native_baseline')
                    else:
                        self.fail('Native failure was lost')
                self.assertEqual(command.call_count, 1)
                self.assertEqual(validate_operation(value, head), value)
                self.assertEqual(value['native_ssh_failure'], expected)
                self.assertNotIn('private', json.dumps(value))

    def test_native_failure_projection_refuses_private_or_malformed_categories(self):
        head = 'a' * 40
        for kind in ('private-peer', 'fixture_native_bound_key_Error_private_1',
                     'fixture_native_bound_key_Error_system_20001',
                     'fixture_native_bound_key_Error_system_01', [], None):
            with self.subTest(kind=kind):
                error = GuestError('private text')
                error.ssh_failure_kind = kind
                value = failure(error, head, 'native_baseline')
                self.assertNotIn('native_ssh_failure', value)
                with self.assertRaises(ValueError):
                    validate_operation({**value, 'native_ssh_failure': kind}, head)

    def test_native_ssh_timeout_keeps_one_command_and_no_child_output(self):
        head = 'a' * 40
        guest = Guest.__new__(Guest)
        guest.directory, guest.ssh_port = Path('private unused directory'), 2222
        with patch('guest.subprocess.run', side_effect=subprocess.TimeoutExpired(
                ['private command'], 1, output=b'private output', stderr=b'private peer')) as command:
            try:
                guest.ssh('private command', 'private operation', timeout=1)
            except GuestError as error:
                value = failure(error, head, 'native_baseline')
            else:
                self.fail('Native timeout was lost')
        self.assertEqual(command.call_count, 1)
        self.assertEqual(validate_operation(value, head), value)
        self.assertEqual(value['native_ssh_failure'], 'command_timeout')
        self.assertNotIn('private', json.dumps(value))

    def test_wrapped_process_timeout_retains_only_its_closed_kind(self):
        head = 'a' * 40
        with patch('linux_guest.subprocess.run', side_effect=subprocess.TimeoutExpired(
                ['private command'], 1, output=b'private stdout', stderr=b'private stderr')):
            try:
                invoke(['private command'], 'Recovery container package installation', timeout=1)
            except RecoveryTimeout as error:
                value = failure(error, head, 'source_prepare')
            else:
                self.fail('Actual process timeout was not retained')
        self.assertEqual(validate_operation(value, head), value)
        self.assertEqual(value['failure_kind'], 'timeout')
        self.assertNotIn('message', value)
        self.assertNotIn('private', json.dumps(value))
        self.assertIs(value['passed'], False)
        self.assertIs(value['full_recovery_or_goal_accepted'], False)

    def test_extra_private_fields_and_missing_proofs_are_refused(self):
        head = 'a' * 40
        value = {'version': 1, 'source_head': head, 'passed': True,
                 **dict.fromkeys(PROOFS, True), **dict.fromkeys(TIMINGS, 1000),
                 'public_operator_durable_custody_renewal_clock_or_full_goal_accepted': False}
        self.assertEqual(validate_operation(value, head), value)
        for field, extra in (('private_url', 'https://private.example'), (PROOFS[0], False), (TIMINGS[0], True)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_operation({**value, field: extra}, head)
        failure = {'version': 1, 'source_head': head, 'passed': False, 'phase': 'checkpoint',
                   'failure_kind': 'other', 'locations': [], 'full_recovery_or_goal_accepted': False}
        self.assertEqual(validate_operation(failure, head), failure)
        with self.assertRaises(ValueError):
            validate_operation({**failure, 'locations': [{'source': '/private/path', 'line': 1}]}, head)

    def test_cleanup_needs_exact_source_and_literal_owned_proofs(self):
        head = 'a' * 40
        value = {'version': 1, 'source_head': head, 'operation_cgroup_reaped': True,
                 'owned_private_VM_disks_keys_and_logs_removed': True,
                 'owned_witness_removed_or_never_started': True, 'witness_was_started': True,
                 'full_recovery_or_goal_accepted': False}
        self.assertEqual(validate_cleanup(value, head), value)
        for key, item in (('source_head', 'b' * 40), ('operation_cgroup_reaped', False), ('private_log', 'fixture')):
            with self.subTest(field=key), self.assertRaises(ValueError):
                validate_cleanup({**value, key: item}, head)


if __name__ == '__main__':
    unittest.main()
