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


if __name__ == '__main__':
    unittest.main()
