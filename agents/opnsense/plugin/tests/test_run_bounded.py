"""Reject invalid or unsupported deadline jobs before executing their command."""
from contextlib import redirect_stderr
import importlib.util
import io
from pathlib import Path
import sys
import unittest


SOURCE = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/nethub-agent/run_bounded.py'
spec = importlib.util.spec_from_file_location('nethub_run_bounded', SOURCE)
bounded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounded)


class BoundedInputTests(unittest.TestCase):
    def test_invalid_duration_and_relative_command_refuse_before_reaper(self):
        for seconds in [0, -1, 301, float('inf'), float('nan')]:
            with self.subTest(seconds=seconds), self.assertRaises(bounded.JobError):
                bounded.run_bounded([sys.executable, '-c', 'raise SystemExit(99)'], seconds)
        with self.assertRaises(bounded.JobError):
            bounded.run_bounded(['python', '-c', 'raise SystemExit(99)'], 1)

    @unittest.skipIf(sys.platform.startswith('freebsd'), 'Unsupported-platform contract')
    def test_unsupported_platform_never_runs_child_or_echoes_its_arguments(self):
        output = io.StringIO()
        with redirect_stderr(output):
            result = bounded.main(['1', sys.executable, '-c', 'raise SystemExit(99)', 'private-marker'])
        self.assertEqual(result, 125)
        self.assertNotIn('private-marker', output.getvalue())
        self.assertNotIn(sys.executable, output.getvalue())


if __name__ == '__main__':
    unittest.main()
