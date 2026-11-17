"""Keep failed TLS preparation closed without turning it into revocation proof."""
import importlib.util
from pathlib import Path
import unittest

from relay_heartbeat import preparation_failure_hints


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('relay_preparation_projection',
    ROOT / 'agents/opnsense/acceptance/compose_setup.py')
PROJECTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROJECTION)


class PreparationFailureTests(unittest.TestCase):
    def test_only_the_exact_exit_code_and_fixed_observations_survive_nested_logs(self):
        hints = preparation_failure_hints(35, False, True, True)
        raw = b'private endpoint, response and credential\n' + '\n'.join(
            'NETHUB_NATIVE_HINT=' + hint for hint in hints).encode() + b'\n'
        first = PROJECTION.project(raw, 1)
        second = PROJECTION.project(PROJECTION.emit(first).encode(), 1)
        self.assertEqual(second['hints'], sorted(hints))
        self.assertNotIn('relay_preparation_curl_exit_3', second['hints'])
        self.assertNotIn('private', str(second))
        self.assertEqual(second['exit_code'], 1)

    def test_unknown_or_out_of_range_markers_cannot_export_private_data(self):
        for marker in ('private credential', 'relay_preparation_curl_exit_256',
                       'relay_preparation_curl_exit_-1', 'relay_preparation_Pong_private'):
            value = PROJECTION.project(('NETHUB_NATIVE_HINT=' + marker + '\n').encode(), 1)
            self.assertEqual(value['hints'], [])
        for values in ((True, False, True, True), (256, False, True, True),
                       (-1, False, True, True), ('private', False, True, True),
                       (0, 'private', True, True), (0, False, None, True), (0, False, True, 1)):
            with self.assertRaises(ValueError):
                preparation_failure_hints(*values)

    def test_a_successful_transport_with_wrong_body_is_still_a_preparation_failure(self):
        hints = preparation_failure_hints(0, False, False, False)
        self.assertEqual(hints, ('relay_preparation_curl_exit_0', 'relay_preparation_body_unmatched',
            'relay_preparation_client_exited', 'relay_preparation_Pong_unobserved'))


if __name__ == '__main__':
    unittest.main()
