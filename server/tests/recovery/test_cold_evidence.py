"""Refuse arbitrary public fields and weakened success/cleanup projections."""
import json
import subprocess
import unittest
from unittest.mock import patch

from cold_evidence import validate_cleanup, validate_operation
from cold_operation import PROOFS, TIMINGS, failure
from linux_guest import RecoveryTimeout, invoke


class ColdEvidenceAdmission(unittest.TestCase):
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
