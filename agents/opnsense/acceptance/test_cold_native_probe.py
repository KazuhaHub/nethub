"""Refuse ambiguous identities before reading any device state."""
import json
import unittest

from cold_native_probe import decode_request


class ColdNativeProbeAdmission(unittest.TestCase):
    def test_only_canonical_bound_device_and_domain_are_admitted(self):
        original = {'nonce': 'a' * 32, 'device_id': '11111111-1111-4111-8111-111111111111',
                    'host': 'abcdefgh.devices.example.test'}
        self.assertEqual(decode_request(json.dumps(original).encode()), original)
        for key, value in (('nonce', 'a' * 31), ('nonce', None), ('device_id', '../other'),
                           ('device_id', '{' + original['device_id'] + '}'),
                           ('host', 'abcdefgh.router.example.com'), ('host', 'abcdefgh.devices.example.test\n')):
            with self.subTest(field=key), self.assertRaises((ValueError, TypeError)):
                decode_request(json.dumps({**original, key: value}).encode())
        for raw in (b'[]', b'{}', b'x' * 4097, json.dumps({**original, 'extra': True}).encode(),
                    json.dumps(original).encode() + b'{}',
                    ('{"nonce":"' + 'a' * 32 + '",' + json.dumps(original)[1:]).encode()):
            with self.subTest(raw_size=len(raw)), self.assertRaises((ValueError, TypeError)):
                decode_request(raw)


if __name__ == '__main__':
    unittest.main()
