"""Check actual systemd oneshot result retention on an isolated hosted runner."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from host_checkpoint import CheckpointError, SourceCheckpoint


HOSTED_ROOT = (sys.platform == 'linux' and os.geteuid() == 0
               and os.environ.get('GITHUB_ACTIONS') == 'true'
               and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
               and re.fullmatch('[a-f0-9]{40}', os.environ.get('NETHUB_SOURCE_HEAD', '')) is not None)


@unittest.skipUnless(HOSTED_ROOT, 'isolated hosted Linux root and systemd required')
class ActualCleanupObservation(unittest.TestCase):
    def setUp(self):
        self.assertEqual(Path('/proc/1/comm').read_text().strip(), 'systemd')
        temporary = tempfile.TemporaryDirectory(prefix='nethub-cleanup-observation-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.checkpoint = object.__new__(SourceCheckpoint)
        self.checkpoint.work = self.root
        self.checkpoint.counter = 0
        self.unit = 'nethub-cold-unit-' + uuid.uuid4().hex + '.service'
        self.unit_file = Path('/run/systemd/system') / self.unit
        self.marker = self.root / 'executed'
        self.unit_created = False
        self.addCleanup(self.remove_unit)

    def command(self, arguments):
        result = subprocess.run(arguments, capture_output=True, timeout=15)
        if result.returncode:
            raise RuntimeError('Owned observation fixture command failed')
        return result.stdout.decode().strip()

    def install(self, *, fails=False):
        executable = '/usr/bin/false' if fails else '/usr/bin/touch ' + str(self.marker)
        with self.unit_file.open('x', encoding='utf-8') as stream:
            self.unit_created = True
            stream.write('[Unit]\nDescription=Owned oneshot observation control\n'
                         '[Service]\nType=oneshot\nExecStart=' + executable + '\nTimeoutStartSec=5s\n')
        self.unit_file.chmod(0o644)
        self.command(['systemctl', 'daemon-reload'])

    def remove_unit(self):
        if not self.unit_created:
            return
        self.command(['systemctl', 'stop', self.unit])
        if self.checkpoint.property(self.unit, 'ActiveState') == 'failed':
            self.command(['systemctl', 'reset-failed', self.unit])
        self.unit_file.unlink(missing_ok=True)
        self.command(['systemctl', 'daemon-reload'])

    def test_unreferenced_successful_oneshot_loses_execution_timestamp(self):
        self.install()
        self.command(['systemctl', 'start', self.unit])
        self.assertTrue(self.marker.is_file())
        deadline = time.monotonic() + 5
        while self.checkpoint.property(self.unit, 'ExecMainStartTimestampMonotonic') != '0':
            if time.monotonic() >= deadline:
                self.fail('Unreferenced oneshot execution state was not collected')
            time.sleep(0.05)

    def test_bounded_reference_preserves_real_fresh_success(self):
        self.install()
        self.checkpoint.fresh_cleanup(self.unit)
        self.assertTrue(self.marker.is_file())

    def test_failed_oneshot_remains_a_failure_with_reference(self):
        self.install(fails=True)
        with self.assertRaises(CheckpointError):
            self.checkpoint.fresh_cleanup(self.unit)
        self.assertFalse(self.marker.exists())


class CleanupObservationAdmission(unittest.TestCase):
    def test_foreign_units_are_refused_before_any_command(self):
        checkpoint = object.__new__(SourceCheckpoint)
        for unit in ('docker.service', '--all', '../nethub-http01-cleanup.service',
                     'nethub-cold-unit-other.service', None, [], True):
            with self.subTest(unit=unit), self.assertRaises(CheckpointError):
                with checkpoint.retain_service_result(unit):
                    self.fail('Foreign observation reference was accepted')
