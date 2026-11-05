"""Failure diagnostics cannot publish raw browser fields or ambiguous JSON."""
import json
import unittest

from traffic_failure import project


class TrafficFailureProjection(unittest.TestCase):
    def baseline(self):
        return {'version': 1, 'phase': 'background_poll', 'failure_kind': 'timeout',
                'last_http_status': 200, 'browser_errors': 0, 'unexpected_proxy_connections': 0,
                'csp_violations': None, 'visible_rows': 2}

    def test_closed_phase_and_counters_are_retained(self):
        result = project(json.dumps(self.baseline()), 1)
        self.assertTrue(result['browser_projection_available'])
        self.assertEqual(result['phase'], 'background_poll')
        self.assertEqual(result['child_exit_code'], 1)

    def test_private_fields_invalid_types_and_unknown_phases_refuse_the_whole_projection(self):
        original = self.baseline()
        for field, value in [('private_error', 'private-host.invalid credential-fixture'),
                             ('phase', 'private-host.invalid'), ('last_http_status', True),
                             ('last_http_status', 600), ('browser_errors', -2), ('visible_rows', 'private data'),
                             ('unexpected_proxy_connections', 1000001), ('failure_kind', 'private data')]:
            raw = json.dumps({**original, field: value})
            with self.subTest(field=field):
                self.assertEqual(project(raw, 1), {'version': 1, 'browser_projection_available': False, 'child_exit_code': 1})
        for raw in ('', '[]', '{}', json.dumps(original) + '{}', '{"version":1,"version":1}', 'x' * 4097):
            self.assertFalse(project(raw, -9)['browser_projection_available'])


if __name__ == '__main__':
    unittest.main()
