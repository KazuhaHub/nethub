"""Keep private failure text and weak success flags out of public outcomes."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import cold_operation as operation
from host_checkpoint import failure_projection, validate_failure
from linux_guest import RecoveryError
from source_host import DeploymentHost


class ClosedRecoveryOutcomes(unittest.TestCase):
    def test_real_checkpoint_cli_emits_bounded_failure_without_traceback_or_inputs(self):
        helper = Path(__file__).with_name('host_checkpoint.py')
        result = subprocess.run([sys.executable, '-B', str(helper), 'private-invalid-action'],
                                capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(len(result.stdout), 4096)
        projected = validate_failure(json.loads(result.stdout))
        self.assertTrue(projected['locations'])
        self.assertEqual({frame['source'] for frame in projected['locations']}, {'host_checkpoint.py'})
        self.assertNotIn(b'private-invalid-action', result.stdout + result.stderr)
        self.assertNotIn(b'Traceback', result.stdout + result.stderr)

    def test_checkpoint_guest_failure_retains_only_allowed_frames(self):
        namespace = {}
        exec(compile("def fail():\n    raise ValueError('private-password private-account')\n",
                     '/private/guest/host_checkpoint.py', 'exec'), namespace)
        try:
            namespace['fail']()
        except ValueError as error:
            projected = failure_projection(error)
        self.assertEqual(projected['locations'], [{'source': 'host_checkpoint.py', 'line': 2}])
        self.assertNotIn('private', json.dumps(projected))
        self.assertEqual(validate_failure(projected), projected)
        for value in ({**projected, 'private': 'secret'}, {**projected, 'version': True},
                      {**projected, 'locations': [{'source': '/private/path', 'line': 1}]},
                      {**projected, 'locations': [{'source': 'host_checkpoint.py', 'line': True}]},
                      {**projected, 'locations': [{'source': [], 'line': 1}]},
                      {**projected, 'locations': projected['locations'] * 9}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_failure(value)

    def test_nonzero_remote_checkpoint_stays_failed_and_exports_no_child_text(self):
        projected = {'version': 1, 'passed': False,
                     'locations': [{'source': 'payload.py', 'line': 40}]}
        with tempfile.TemporaryDirectory() as directory:
            host = object.__new__(DeploymentHost)
            host.work = host.repository = Path(directory)
            host.counter = 0
            for label, phase in (
                    ('Original complete protected-host checkpoint', 'checkpoint'),
                    ('Distinct full protected-host recovery', 'target_restore'),
                    ('Fresh target cleanup and stock timer resumption', 'timer_resume')):
                for raw, expected in ((json.dumps(projected).encode(), projected['locations']),
                                      (b'private child output', []),
                                      (json.dumps({**projected, 'secret': 'private'}).encode(), []),
                                      (b'x' * 4097, [])):
                    with self.subTest(label=label, expected=expected):
                        result = subprocess.CompletedProcess([], 1, raw, b'private stderr')
                        with patch('source_host.subprocess.run', return_value=result):
                            with self.assertRaises(RecoveryError) as caught:
                                host.command(['unexecuted'], label)
                        value = operation.failure(caught.exception, 'a' * 40, phase)
                        inner = [item for item in value['locations'] if item['source'] == 'payload.py']
                        self.assertEqual(inner, expected)
                        self.assertFalse(value['passed'])
                        self.assertNotIn('private', json.dumps(value))

    def test_unvalidated_checkpoint_metadata_cannot_enter_public_failure(self):
        error = RecoveryError('private error')
        error.checkpoint_failure = {'secret': 'private'}
        self.assertEqual(operation.failure(error, 'a' * 40, 'checkpoint')['locations'], [])
        error.checkpoint_failure = {'version': 1, 'passed': False,
                                    'locations': [{'source': 'payload.py', 'line': 40}]}
        self.assertEqual(operation.failure(error, 'a' * 40, 'native_request')['locations'], [])

    def test_failure_never_exports_private_exception_text_or_arbitrary_source(self):
        private = 'private-password https://unrelated.example/ private-account-key'
        try:
            raise ValueError(private)
        except ValueError as error:
            result = operation.failure(error, 'a' * 40, private)
        self.assertNotIn(private, json.dumps(result))
        self.assertEqual(result['phase'], 'unavailable')
        self.assertEqual(result['locations'], [])
        self.assertFalse(result['passed'])

    def test_success_requires_all_proofs_and_real_bounded_integer_timings(self):
        value = {**dict.fromkeys(operation.PROOFS, True), **dict.fromkeys(operation.TIMINGS, 1234),
                 'public_operator_durable_custody_renewal_clock_or_full_goal_accepted': False,
                 'private_password': 'fixture secret'}
        result = operation.success(value, 'a' * 40)
        self.assertTrue(result['passed'])
        self.assertNotIn('private_password', result)
        for field in operation.PROOFS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                operation.success({**value, field: False}, 'a' * 40)
        for field in operation.TIMINGS:
            for invalid in (True, 0, -1, 7200001, '1234'):
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    operation.success({**value, field: invalid}, 'a' * 40)


if __name__ == '__main__':
    unittest.main()
