"""Private hook logs produce only bounded counts for known decision labels."""
import json
import unittest

from hook_probe import DECISIONS, project, project_rejected_sources


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

    def test_actual_rejection_source_is_compared_without_exporting_addresses(self):
        lines = [b'prefix the user conn [192.0.2.10:1234] was rejected, err:not_authorized',
                 b'prefix the user conn [[::ffff:192.0.2.10]:2345] was rejected, err:not_authorized',
                 b'prefix the user conn [127.0.0.1:3456] was rejected, err:private-detail',
                 b'prefix the user conn [[2001:4860:4860::8888]:4567] was rejected, err:not_authorized']
        raw = b'\n'.join(lines)
        result = project_rejected_sources(raw, '192.0.2.10')
        self.assertEqual(result, {'version': 1, 'available': True, 'rejected_entries': 4,
            'source_matches_open': 2, 'source_differs_from_open': 2,
            'loopback': 1, 'private': 2, 'other': 1})
        for private in ('192.0.2.10', '127.0.0.1', '2001:4860', 'private-detail', '1234'):
            self.assertNotIn(private, str(result))

    def test_missing_or_json_reflected_source_is_explicitly_unavailable(self):
        raw = json.dumps({'private': 'the user conn [192.0.2.10:1234] was rejected, err:value'}).encode()
        result = project_rejected_sources(raw, '192.0.2.10')
        self.assertIs(result['available'], False)
        self.assertEqual(result['rejected_entries'], 0)
        self.assertEqual(result['source_matches_open'], 0)

    def test_malformed_or_unbounded_source_observations_are_refused_without_echo(self):
        for address in ('private.example:1234', '192.0.2.10:0', '192.0.2.10:65536',
                        '[fe80::1%private]:1234', '0.0.0.0:1234', '224.0.0.1:1234'):
            raw = ('the user conn [' + address + '] was rejected, err:private-detail').encode()
            with self.assertRaises(ValueError) as caught:
                project_rejected_sources(raw, '192.0.2.10')
            self.assertEqual(str(caught.exception), 'Restored rejected-source observation unavailable')
        for raw, expected in ((b'x' * (256 * 1024 + 1), '192.0.2.10'),
                              (b'x\n' * 1025, '192.0.2.10'), (b'', True), (b'', 'private.example')):
            with self.assertRaises(ValueError) as caught:
                project_rejected_sources(raw, expected)
            self.assertEqual(str(caught.exception), 'Restored rejected-source observation unavailable')
