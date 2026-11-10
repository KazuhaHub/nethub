from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from linux_guest import RecoveryError, RecoveryTimeout
from probe import failure_message


class ClosedPreparationFailure(unittest.TestCase):
    def test_runtime_phase_and_outcome_survive_the_entry_point_projection(self):
        for stage in ('Recovery package metadata refresh',
                      'Recovery container package installation',
                      'Recovery container service startup'):
            for outcome in ('failed', 'unavailable', 'timed out'):
                label = stage + ' ' + outcome
                with self.subTest(label=label):
                    self.assertEqual(failure_message(RecoveryError(label)),
                                     'Recovery target preparation failed: ' + label)
        label = 'Recovery container runtime preparation timed out'
        self.assertEqual(failure_message(RecoveryError(label)),
                         'Recovery target preparation failed: ' + label)

    def test_unknown_and_near_matching_errors_keep_all_details_private(self):
        errors = [
            RecoveryError('Recovery package metadata refresh failed: private output'),
            RecoveryError('Recovery package metadata refresh timed out\nprivate path'),
            OSError('Recovery package metadata refresh timed out'),
            subprocess.TimeoutExpired('private command', 1, output=b'private stdout', stderr=b'private stderr'),
            ValueError('private material'),
        ]
        for error in errors:
            with self.subTest(error_type=type(error).__name__):
                self.assertEqual(failure_message(error),
                                 'Recovery target preparation failed; inspect private runner state')

    def test_actual_entry_point_keeps_failed_result_and_cleanup_without_private_output(self):
        errors = [RecoveryError('Recovery container package installation failed'),
                  RecoveryTimeout('Recovery container package installation timed out'),
                  ValueError('private argument and output')]
        for error in errors:
            guest = Mock()
            guest.process.poll.return_value = None
            guest.prepare.side_effect = error
            guest.__enter__ = Mock(return_value=guest)
            def cleanup(*args):
                guest.process.poll.return_value = 0
            guest.__exit__ = Mock(side_effect=cleanup)
            with self.subTest(error_type=type(error).__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                evidence = root / 'evidence'
                stderr = io.StringIO()
                arguments = ['probe.py', '--directory', str(root / 'guest'), '--evidence', str(evidence)]
                with patch.dict(os.environ, {'NETHUB_SOURCE_HEAD': 'a' * 40, 'RUNNER_TEMP': str(root)}), \
                     patch('sys.argv', arguments), patch('signal.signal'), \
                     patch('linux_guest.LinuxGuest', return_value=guest), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        runpy.run_path(str(Path(__file__).with_name('probe.py')), run_name='__main__')
                self.assertEqual(raised.exception.code, 1)
                self.assertEqual(stderr.getvalue().strip(), failure_message(error))
                self.assertNotIn('private argument', stderr.getvalue())
                outcome = json.loads((evidence / 'target-result.json').read_text())
                self.assertEqual(outcome['phase'], 'prepare')
                self.assertIs(outcome['target_prepared'], False)
                self.assertIs(outcome['owned_guest_stopped'], True)
                self.assertIs(outcome['full_goal_complete'], False)
                self.assertNotIn('failure', outcome)
                guest.__exit__.assert_called_once()


if __name__ == '__main__':
    unittest.main()
