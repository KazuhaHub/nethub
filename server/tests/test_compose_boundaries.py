"""Exercise acceptance command deadlines without requiring a Docker daemon."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


class ComposeCommandBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='nethub-compose-boundary-')
        self.addCleanup(self.temporary.cleanup)
        self.stage = Path(self.temporary.name)
        source = (Path(__file__).parent / 'compose.sh').read_text()
        self.definition = source[source.index('compose_for() ('):source.index('cleanup() {')]
        self.check = source[source.index('repeat_status=0'):source.index('python3 - "$stage"', source.index('repeat_status=0'))]
        self.shell = os.environ.get('NETHUB_TEST_SHELL') or shutil.which('sh')
        self.assertTrue(self.shell, 'A POSIX shell and GNU timeout are required')
        stub = self.stage / 'docker'
        stub.write_text('#!/bin/sh\nif [ "$STUB_MODE" = hang ]; then sleep 20; fi\nprintf "%s\\n" "$STUB_TEXT"\nexit "$STUB_EXIT"\n')
        stub.chmod(0o755)
        (self.stage / 'admin-password').write_text('public-fixture-input\n')

    def invoke(self, body, code, text='', mode='normal'):
        script = self.stage / 'case.sh'
        script.write_text('stage=$(pwd)\nproject=public-test\nPATH="$stage:/usr/bin:/bin"\n' + self.definition + body)
        return subprocess.run([self.shell, str(script)], cwd=self.stage,
                              env=dict(os.environ, STUB_EXIT=str(code), STUB_TEXT=text, STUB_MODE=mode),
                              capture_output=True, timeout=12)

    def test_repeat_bootstrap_requires_account_refusal(self):
        expected = 'Accounts already exist; initial administrator creation is closed'
        for code, text, accepted in [(1, expected, True), (124, expected, False),
                                     (0, expected, False), (1, 'Docker daemon unavailable', False)]:
            with self.subTest(code=code, text=text):
                result = self.invoke(self.check, code, text)
                self.assertEqual(result.returncode == 0, accepted)

    def test_command_deadline_preserves_timeout_failure(self):
        started = time.monotonic()
        result = self.invoke('compose_for 1 config\n', 0, mode='hang')
        self.assertEqual(result.returncode, 124)
        self.assertLess(time.monotonic() - started, 5)


if __name__ == '__main__':
    unittest.main()
