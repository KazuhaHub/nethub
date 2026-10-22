"""Exercise actual FreeBSD reaping, daemon handoff, deadlines and cancellation."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


SOURCE = Path(os.environ.get('NETHUB_BOUNDED_SOURCE', str(
    Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/scripts/nethub-agent/run_bounded.py')))


@unittest.skipUnless(sys.platform.startswith('freebsd'), 'Actual FreeBSD procctl and timeout contract')
class NativeBoundedTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='nethub-deadline-')
        self.root = Path(self.directory.name)
        self.nonce = uuid.uuid4().hex
        self.child_pid = self.root / 'daemon.pid'

    def alive(self, pid):
        result = subprocess.run(['/bin/ps', '-o', 'state=', '-p', str(pid)], capture_output=True, text=True, timeout=3)
        return result.returncode == 0 and result.stdout.strip()[:1] not in ('', 'Z', 'X')

    def tearDown(self):
        if self.child_pid.exists():
            pid = int(self.child_pid.read_text())
            if self.alive(pid):
                args = subprocess.check_output(['/bin/ps', '-ww', '-o', 'args=', '-p', str(pid)], text=True, timeout=3)
                self.assertIn(self.nonce, args)
                os.kill(pid, signal.SIGKILL)
        self.directory.cleanup()

    def spawn_command(self, hang=False):
        child = 'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)'
        source = (
            'import pathlib,subprocess,sys,time;'
            'p=subprocess.Popen([sys.executable,"-c",sys.argv[2],sys.argv[3]],'
            'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,'
            'close_fds=True,start_new_session=True);'
            'pathlib.Path(sys.argv[1]).write_text(str(p.pid));'
            + ('time.sleep(30)' if hang else 'raise SystemExit(0)')
        )
        return [sys.executable, '-c', source, str(self.child_pid), child, self.nonce]

    def test_completed_job_hands_off_daemon_without_waiting(self):
        started = time.monotonic()
        result = subprocess.run([sys.executable, str(SOURCE), '2', *self.spawn_command()], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - started, 5)
        self.assertTrue(self.alive(int(self.child_pid.read_text())))

    def test_deadline_kills_detached_sigterm_ignoring_descendant(self):
        result = subprocess.run([sys.executable, str(SOURCE), '2', *self.spawn_command(hang=True)], capture_output=True, timeout=12)
        self.assertEqual(result.returncode, 124)
        self.assertFalse(self.alive(int(self.child_pid.read_text())))

    def test_cancellation_kills_owned_descendants(self):
        child = subprocess.Popen([sys.executable, str(SOURCE), '20', *self.spawn_command(hang=True)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            until = time.monotonic() + 6
            while not self.child_pid.exists() and time.monotonic() < until:
                self.assertIsNone(child.poll())
                time.sleep(.02)
            self.assertTrue(self.child_pid.exists())
            # Let the detached child install its TERM handler before cancellation.
            time.sleep(.2)
            child.terminate()
            self.assertEqual(child.wait(timeout=8), 143)
            self.assertFalse(self.alive(int(self.child_pid.read_text())))
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)

    def test_stock_timeout_waits_for_daemon_after_successful_parent_exit(self):
        result = subprocess.run(['/usr/bin/timeout', '-k', '1', '2', *self.spawn_command()], capture_output=True, timeout=9)
        self.assertEqual(result.returncode, 124)
        self.assertFalse(self.alive(int(self.child_pid.read_text())))

    def test_exit_status_is_preserved(self):
        result = subprocess.run([sys.executable, str(SOURCE), '2', sys.executable, '-c', 'raise SystemExit(17)'],
                                capture_output=True, timeout=6)
        self.assertEqual(result.returncode, 17)


if __name__ == '__main__':
    unittest.main()
