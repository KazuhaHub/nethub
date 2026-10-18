"""Verify persistent rollback quarantine across watchdog and reconcile runs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

import test_reconcile as fixture

ROOT, VALID = fixture.ROOT, fixture.VALID

SPEC = importlib.util.spec_from_file_location('watchdog', ROOT / 'src/usr/local/opnsense/scripts/nethub-agent/watchdog.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.ReconcileTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.active = False
        self.agent = self.fixture.agent
        self.agent.state.mkdir(parents=True)
        self.bad = VALID.replace('device-test', 'device-bad')
        self.agent.live.write_text(self.bad)
        self.agent.backup.write_text(VALID)
        self.fixture.render = self.bad
        self.watchdog = MODULE.Watchdog(self.fixture.root, self.fixture.command)

    def test_rollback_is_persistent_and_bad_desired_config_stays_quarantined(self):
        self.assertTrue(self.watchdog.apply()['success'])
        self.assertEqual(self.agent.live.read_text(), VALID)
        recovery = json.loads(self.watchdog.journal.read_text())
        self.assertEqual(recovery['rejected_sha256'], hashlib.sha256(self.bad.encode()).hexdigest())
        self.assertTrue(recovery['attempted'])
        self.assertFalse(recovery['abandoned'])
        self.assertEqual(self.agent.apply('reconcile')['action'], 'quarantined')
        self.assertEqual(self.agent.live.read_text(), VALID)
        self.fixture.active = False
        self.assertEqual(self.watchdog.apply()['action'], 'already_attempted')
        self.assertEqual(self.agent.apply('reconcile')['action'], 'quarantined')
        self.assertEqual(self.fixture.mutations(), ['onestart'])

    def test_different_validated_desired_config_releases_quarantine(self):
        self.watchdog.apply()
        self.fixture.render = VALID.replace('device-test', 'device-next')
        self.assertTrue(self.agent.apply('reconcile')['success'])
        self.assertFalse(self.watchdog.journal.exists())
        self.assertEqual(self.agent.live.read_text(), self.fixture.render)

    def test_failed_recovery_is_not_repeated_or_started_by_reconcile(self):
        def fail_start(args, **kwargs):
            if str(args[-1]) == 'onestart':
                self.fixture.calls.append(list(args))
                return subprocess.CompletedProcess(args, 1, '', '')
            return self.fixture.command(args, **kwargs)
        self.watchdog.runner = fail_start
        self.assertFalse(self.watchdog.apply()['success'])
        self.assertTrue(json.loads(self.watchdog.journal.read_text())['abandoned'])
        self.assertEqual(self.watchdog.apply()['action'], 'already_attempted')
        self.assertEqual(self.agent.apply('reconcile')['action'], 'quarantined')
        self.assertEqual(self.fixture.mutations(), ['onestart'])

    def test_no_backup_abandons_without_restart(self):
        self.agent.backup.unlink()
        self.assertEqual(self.watchdog.apply()['action'], 'no_last_good')
        self.assertEqual(self.agent.apply('reconcile')['action'], 'quarantined')
        self.assertEqual(self.fixture.mutations(), [])

    def test_disabled_revoked_and_operator_stopped_never_restart(self):
        for marker in ['disabled', 'revoked', 'stopped', 'uninstalling']:
            with self.subTest(marker=marker):
                p = self.agent.state / marker
                p.touch()
                self.assertEqual(self.watchdog.apply()['action'], 'disabled')
                self.assertTrue(self.agent.apply('reconcile')['success'])
                self.assertFalse(self.watchdog.journal.exists())
                p.unlink()
        self.assertEqual(self.fixture.mutations(), [])

    def test_revocation_is_not_cleared_by_explicit_start(self):
        (self.agent.state / 'revoked').touch()
        self.agent.apply('start')
        self.assertFalse(self.fixture.active)
        self.assertEqual(self.watchdog.apply()['action'], 'disabled')

    def test_invalid_recovery_state_fails_closed(self):
        for payload in [{'version': 1}, {'version': 1, 'rejected_sha256': None}, [], None]:
            with self.subTest(payload=payload):
                self.watchdog.journal.write_text(json.dumps(payload))
                self.assertEqual(self.watchdog.apply()['action'], 'invalid_recovery_state')
                self.assertFalse(self.agent.apply('reconcile')['success'])
        self.assertEqual(self.fixture.mutations(), [])

    @unittest.skipUnless(Path('/usr/bin/lockf').exists(), 'Native FreeBSD lockf check')
    def test_native_lockf_excludes_both_python_operations(self):
        import fcntl
        lock = self.agent.state / 'reconcile.lock'
        with lock.open('a') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = subprocess.run(['/usr/bin/lockf', '-sk', '-t', '0', str(lock), '/usr/bin/true'])
            self.assertEqual(result.returncode, 75)
            self.assertEqual(self.watchdog.apply()['action'], 'skipped')
            self.assertEqual(self.agent.apply('reconcile')['action'], 'busy')


if __name__ == '__main__':
    unittest.main()
