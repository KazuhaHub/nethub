"""Private hook logs produce only bounded counts for known decision labels."""
import json
import unittest

from hook_probe import DECISIONS, project


class ClosedHookDecisions(unittest.TestCase):
    def test_counts_only_connection_decisions_without_other_metadata(self):
        rows = [{'msg': 'Relay hook decision', 'operation': operation, 'decision': decision,
                 'private': 'private-address-and-credential'}
                for operation, decision in [('NewUserConn', 'allowed'), ('NewUserConn', 'device_denied'),
                                            ('Login', 'allowed'), ('NewUserConn', 'device_denied')]]
        value = project(b'private non-JSON output\n' + b'\n'.join(json.dumps(row).encode() for row in rows))
        expected = dict.fromkeys(DECISIONS, 0)
        expected.update(allowed=1, device_denied=2)
        self.assertEqual(value, {'version': 1, 'connection_decisions': expected})
        self.assertNotIn('private', str(value))

    def test_unknown_or_duplicate_decision_is_refused_without_echo(self):
        for raw in (json.dumps({'msg': 'Relay hook decision', 'operation': 'NewUserConn',
                               'decision': 'private-unknown-value'}).encode(),
                    b'{"msg":"Relay hook decision","operation":"NewUserConn",'
                    b'"decision":"allowed","decision":"private-value"}'):
            with self.assertRaises(ValueError) as caught:
                project(raw)
            self.assertEqual(str(caught.exception), 'Restored connection-hook observation unavailable')

    def test_oversized_logs_or_excess_lines_are_refused(self):
        for raw in (b'x' * (256 * 1024 + 1), b'x\n' * 1025):
            with self.assertRaises(ValueError) as caught:
                project(raw)
            self.assertEqual(str(caught.exception), 'Restored connection-hook observation unavailable')
