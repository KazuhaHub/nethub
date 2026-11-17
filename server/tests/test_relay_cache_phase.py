"""Reject callback failures and ambiguous observations as publication evidence."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from relay_cache_phase import cutoff_ms, ping_decision, publication_bracket


class CachePhaseEvidenceTests(unittest.TestCase):
    def test_rounding_cannot_turn_a_late_observation_into_a_pass(self):
        self.assertEqual(cutoff_ms(10., 15.), 5000)
        self.assertEqual(round((15.0004 - 10.) * 1000), 5000)
        with self.assertRaises(ValueError):
            cutoff_ms(10., 15.0004)

    def test_invalid_or_reversed_clocks_cannot_supply_a_cutoff(self):
        for started, observed in [(0, 1), (10, 9), (True, 2), (1, float('inf')),
                (1, float('nan')), (float('inf'), float('inf'))]:
            with self.subTest(started=started, observed=observed), self.assertRaises(ValueError):
                cutoff_ms(started, observed)

    def test_only_exact_allow_and_authorization_denial_are_anchors(self):
        self.assertEqual(ping_decision(200, b'{"reject":false,"unchange":true}'), 'allowed')
        self.assertEqual(ping_decision(200, b'{"reject":true,"reject_reason":"not_authorized"}'), 'denied')

    def test_unavailable_and_transport_failures_do_not_look_like_publication(self):
        for status, raw in [(503, b'{"reject":true,"reject_reason":"not_authorized"}'),
                (200, b'{"reject":true,"reject_reason":"unavailable"}'), (200, b''),
                (200, b'x' * 1025), (200, b'null'), (200, b'[]')]:
            with self.subTest(status=status, raw=raw[:80]), self.assertRaises(ValueError):
                ping_decision(status, raw)

    def test_duplicate_keys_boolean_coercion_and_extensions_are_refused(self):
        for raw in [b'{"reject":true,"reject":false,"unchange":true}',
                b'{"reject":0,"unchange":true}', b'{"reject":false,"unchange":1}',
                b'{"reject":true,"reject_reason":"not_authorized","unchange":false}',
                b'{"reject":false,"unchange":true,"extra":null}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ping_decision(200, raw)

    def test_publication_is_bracketed_not_claimed_at_response_time(self):
        value = publication_bracket({'started': 10.0, 'finished': 10.01, 'decision': 'allowed'},
            {'started': 10.02, 'finished': 10.03, 'decision': 'denied'})
        self.assertEqual(value, {'earliest': 10.0, 'latest': 10.03, 'uncertainty_ms': 30.0})

    def test_wide_overlapping_reversed_or_nonfinite_observations_are_refused(self):
        allowed = {'started': 10., 'finished': 10.01, 'decision': 'allowed'}
        for denied in [{'started': 10.02, 'finished': 10.2, 'decision': 'denied'},
                {'started': 10.005, 'finished': 10.03, 'decision': 'denied'},
                {'started': 9., 'finished': 9.01, 'decision': 'denied'},
                {'started': 10.02, 'finished': 10.03, 'decision': 'allowed'},
                {'started': 10.02, 'finished': float('inf'), 'decision': 'denied'},
                {'started': float('nan'), 'finished': 10.03, 'decision': 'denied'},
                {'started': True, 'finished': 10.03, 'decision': 'denied'}]:
            with self.subTest(denied=denied), self.assertRaises(ValueError):
                publication_bracket(allowed, denied)


if __name__ == '__main__':
    unittest.main()
