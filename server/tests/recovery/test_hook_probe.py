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
        self.assertEqual(value, {'version': 2, 'connection_decisions': expected,
            'denial_causes': {'device_state': 0, 'source_access': 0, 'unavailable': 2}})
        self.assertNotIn('private', str(value))

    def test_unknown_or_duplicate_decision_is_refused_without_echo(self):
        for raw in (json.dumps({'msg': 'Relay hook decision', 'operation': 'NewUserConn',
                               'decision': 'private-unknown-value'}).encode(),
                    b'{"msg":"Relay hook decision","operation":"NewUserConn",'
                    b'"decision":"allowed","decision":"private-value"}'):
            with self.assertRaises(ValueError) as caught:
                project(raw)
            self.assertEqual(str(caught.exception), 'Restored connection-hook observation unavailable')

    def test_fixed_denial_causes_are_counted_and_unknown_causes_refused(self):
        row = {'msg': 'Relay hook decision', 'operation': 'NewUserConn', 'decision': 'device_denied'}
        rows = [{**row, 'cause': value, 'private': 'private-address'} for value in ('device_state', 'source_access')]
        result = project(b'\n'.join(json.dumps(value).encode() for value in rows))
        self.assertEqual(result['denial_causes'], {'device_state': 1, 'source_access': 1, 'unavailable': 0})
        self.assertNotIn('private', str(result))
        with self.assertRaises(ValueError) as caught:
            project(json.dumps({**row, 'cause': 'private-cause'}).encode())
        self.assertEqual(str(caught.exception), 'Restored connection-hook observation unavailable')

    def test_oversized_logs_or_excess_lines_are_refused(self):
        for raw in (b'x' * (256 * 1024 + 1), b'x\n' * 1025):
            with self.assertRaises(ValueError) as caught:
                project(raw)
            self.assertEqual(str(caught.exception), 'Restored connection-hook observation unavailable')
