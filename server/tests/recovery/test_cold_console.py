"""Refuse redirected, privileged or noncanonical console fixture mutations."""
import unittest
from unittest.mock import patch

from cold_console import ColdConsole, canonical_device, permitted_request
from linux_guest import RecoveryError


class ConsoleAdmission(unittest.TestCase):
    def test_only_normal_login_enrollment_and_canonical_open_are_allowed(self):
        device = '11111111-1111-4111-8111-111111111111'
        self.assertTrue(canonical_device(device))
        for method, path in (('POST', '/api/v1/console/login'), ('POST', '/api/v1/console/enroll-tokens'),
                             ('GET', '/api/v1/console/devices'), ('POST', '/api/v1/console/devices/' + device + '/open')):
            self.assertTrue(permitted_request(method, path))
        for method, path in (('PATCH', '/api/v1/console/devices'), ('DELETE', '/api/v1/console/devices/' + device),
                             ('POST', '/api/v1/console/users'), ('POST', '//unrelated.example/login'),
                             ('POST', '/api/v1/console/login?redirect=https://unrelated.example'),
                             ('POST', '/api/v1/console/devices/../open'),
                             ('POST', '/api/v1/console/devices/{' + device + '}/open'),
                             ('POST', '/api/v1/console/devices/' + device + '/open/extra')):
            with self.subTest(method=method, path=path):
                self.assertFalse(permitted_request(method, path))
        for value in (None, '', [], 'not-a-device', '{' + device + '}'):
            self.assertFalse(canonical_device(value))

    def test_ambiguous_token_creation_is_not_replayed(self):
        console = object.__new__(ColdConsole)
        with patch.object(console, 'request', side_effect=RecoveryError('fixture lost reply')) as request:
            with self.assertRaises(RecoveryError):
                console.enrollment_token()
            with self.assertRaises(RecoveryError):
                console.enrollment_token()
            self.assertEqual(request.call_count, 1)


if __name__ == '__main__':
    unittest.main()
