"""Keep private failure text and weak success flags out of public outcomes."""
import json
import unittest

import cold_operation as operation


class ClosedRecoveryOutcomes(unittest.TestCase):
    def test_failure_never_exports_private_exception_text_or_arbitrary_source(self):
        private = 'private-password https://unrelated.example/ private-account-key'
        try:
            raise ValueError(private)
        except ValueError as error:
            result = operation.failure(error, 'a' * 40, private)
        self.assertNotIn(private, json.dumps(result))
        self.assertEqual(result['phase'], 'unavailable')
        self.assertEqual(result['locations'], [])
        self.assertFalse(result['passed'])

    def test_success_requires_all_proofs_and_real_bounded_integer_timings(self):
        value = {**dict.fromkeys(operation.PROOFS, True), **dict.fromkeys(operation.TIMINGS, 1234),
                 'public_operator_durable_custody_renewal_clock_or_full_goal_accepted': False,
                 'private_password': 'fixture secret'}
        result = operation.success(value, 'a' * 40)
        self.assertTrue(result['passed'])
        self.assertNotIn('private_password', result)
        for field in operation.PROOFS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                operation.success({**value, field: False}, 'a' * 40)
        for field in operation.TIMINGS:
            for invalid in (True, 0, -1, 7200001, '1234'):
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    operation.success({**value, field: invalid}, 'a' * 40)


if __name__ == '__main__':
    unittest.main()
