"""Reject unsafe rollout order, unrelated config changes and ambiguous TCP witnesses."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('relay_migration', Path(__file__).with_name('relay_migration.py'))
MIGRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MIGRATION)


def connection(pid, inode, source='127.0.0.1:50001', destination='127.0.0.1:7000'):
    return f'ESTAB 0 0 {source} {destination} users:(("frpc",pid={pid},fd=7)) uid:1000 ino:{inode} sk:abcd\n'


class MigrationBoundaryTests(unittest.TestCase):
    def test_old_clients_require_widening_before_upgrade_or_rollback(self):
        for timings in ([(10, 30)], [(1, 3), (10, 30)], [(10, 30), (10, 30)]):
            MIGRATION.require_compatible(30, timings)
            with self.assertRaises(ValueError):
                MIGRATION.require_compatible(3, timings)
        MIGRATION.require_compatible(3, [(1, 3), (1, 3)])

    def test_unknown_and_boolean_profiles_do_not_relax_the_rollout_guard(self):
        for timeout, timings in [(True, [(1, 3)]), (10, [(1, 3)]), (3, []),
                (3, [(True, 3)]), (30, [(10, True)]), (30, [(10, 20)]), (30, [[10, 30]])]:
            with self.subTest(timeout=timeout, timings=timings), self.assertRaises(ValueError):
                MIGRATION.require_compatible(timeout, timings)

    def test_timeout_change_preserves_all_other_bytes_and_can_restore_exactly(self):
        for newline in (b'\n', b'\r\n'):
            original = newline.join([b'bindPort = 7000', b'transport.heartbeatTimeout = 3',
                b'auth.token = "owned fixture"', b'transport.tls.force = true', b''])
            widened = MIGRATION.timeout_config(original, 30)
            self.assertEqual(widened, original.replace(b'heartbeatTimeout = 3', b'heartbeatTimeout = 30'))
            self.assertEqual(MIGRATION.timeout_config(widened, 3), original)

    def test_unexpected_config_shapes_and_timeouts_are_not_rewritten(self):
        for raw in (b'bindPort = 7000\n', b'transport.heartbeatTimeout = 10\n',
                    b'transport.heartbeatTimeout = true\n', b'transport.heartbeatTimeout = 3\ntransport.heartbeatTimeout = 3\n',
                    b'[transport]\nheartbeatTimeout = 3\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                MIGRATION.timeout_config(raw, 30)
        for timeout in (True, 0, 10, '30'):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                MIGRATION.timeout_config(b'transport.heartbeatTimeout = 3\n', timeout)

    def test_original_pid_and_inode_are_both_bound_including_ipv6(self):
        raw = connection(12, 200) + connection(112, 201, '[::1]:50002', '[::1]:7000')
        self.assertEqual(MIGRATION.control_bindings(raw, [12, 112]),
            {12: ('127.0.0.1:50001', '127.0.0.1:7000', '200'),
             112: ('[::1]:50002', '[::1]:7000', '201')})
        self.assertEqual(MIGRATION.control_bindings(connection(112, 201), [12]), {12: None})

    def test_disconnected_or_unrelated_connections_cannot_supply_a_witness(self):
        raw = connection(12, 200).replace('ESTAB', 'SYN-SENT')
        raw += connection(12, 201, destination='127.0.0.1:8443') + connection(112, 202)
        self.assertEqual(MIGRATION.control_bindings(raw, [12]), {12: None})

    def test_missing_duplicate_shared_or_zero_inodes_are_refused(self):
        for raw in (connection(12, 200).replace('ino:200', ''), connection(12, 0),
                    connection(12, 200) + connection(12, 201),
                    connection(12, 200) + connection(13, 200),
                    connection(12, 200).replace('pid=12,', 'pid=12,pid=13,')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                MIGRATION.control_bindings(raw, [12, 13])

    def test_invalid_observer_inputs_cannot_produce_empty_success(self):
        for raw, pids in [(b'', [12]), ('x' * (1024**2 + 1), [12]), ('', []),
                          ('', [True]), ('', [0]), ('', [12, 12]), ('', 12)]:
            with self.subTest(pids=pids), self.assertRaises(ValueError):
                MIGRATION.control_bindings(raw, pids)


class ClientFailureClassificationTests(unittest.TestCase):
    def test_command_line_problems_are_closed_categories(self):
        binary = Path('/opt/fixture/frpc')
        good = [str(binary).encode(), b'-c', b'/stage/relay-test/client.json']
        self.assertIsNone(MIGRATION.client_command_problem(good, binary))
        self.assertEqual(MIGRATION.client_command_problem([b''], binary), 'client_argument_count')
        self.assertEqual(MIGRATION.client_command_problem([], binary), 'client_argument_count')
        self.assertEqual(MIGRATION.client_command_problem([b'/usr/bin/other', b'-c', b'x'], binary),
                         'client_binary_mismatch')
        self.assertEqual(MIGRATION.client_command_problem([str(binary).encode(), b'-x', b'x'], binary),
                         'client_flag_mismatch')

    def test_exited_client_reports_status_and_login_flag_without_log_text(self):
        secret = b'token=owned-fixture-secret'
        log = secret + b' login to the server failed: refused. With loginFailExit enabled'
        message = MIGRATION.describe_client_failure('client_argument_count', False, 1, log)
        self.assertEqual(message, 'migration client exited: exit_code=1 running_at_check=False '
                                  'login_failure_logged=True command=client_argument_count')
        self.assertNotIn('owned-fixture-secret', message)
        self.assertIn('login_failure_logged=False',
                      MIGRATION.describe_client_failure('client_argument_count', True, -15, b'other'))
        self.assertIn('login_failure_logged=unknown',
                      MIGRATION.describe_client_failure('client_argument_count', False, 0, None))

    def test_running_client_mismatch_and_invalid_status(self):
        self.assertEqual(MIGRATION.describe_client_failure('client_flag_mismatch', True, None, b'x'),
                         'migration client client_flag_mismatch while running')
        for code in (True, '1', 1.0):
            with self.subTest(code=code), self.assertRaises(ValueError):
                MIGRATION.describe_client_failure('client_argument_count', False, code, b'')
        with self.assertRaises(ValueError):
            MIGRATION.describe_client_failure('client_argument_count', 1, 0, b'')

    def test_classification_wiring_with_real_processes(self):
        import subprocess, sys, tempfile
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'client.log'
            log.write_bytes(b'login to the server failed: x')
            exited = subprocess.Popen([sys.executable, '-c', 'raise SystemExit(1)'])
            exited.wait()
            self.assertEqual(MIGRATION.classify_client_failure('client_argument_count', exited, log),
                             'migration client exited: exit_code=1 running_at_check=False '
                             'login_failure_logged=True command=client_argument_count')
            self.assertIn('login_failure_logged=unknown',
                          MIGRATION.classify_client_failure('client_argument_count', exited, None))
            self.assertIn('login_failure_logged=unknown',
                          MIGRATION.classify_client_failure('client_argument_count', exited,
                                                            Path(directory) / 'missing.log'))
            running = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            try:
                self.assertEqual(MIGRATION.classify_client_failure('client_binary_mismatch', running, log),
                                 'migration client client_binary_mismatch while running')
            finally:
                running.kill()
                running.wait()


if __name__ == '__main__':
    unittest.main()
