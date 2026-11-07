"""Refuse off-witness account paths, CA endpoints and forwarding metadata."""
import unittest

from witness_contract import valid_ready


class WitnessReadyAdmission(unittest.TestCase):
    def test_only_matching_owned_CA_paths_and_peer_endpoint_are_admitted(self):
        control = '/tmp/owned-runner/nethub-cold-witness-' + 'a' * 16
        stage = control + '/tmp/TestColdHostACMEWitness123/001'
        host = 'abcdefgh.devices.example.test'
        ready = {'version': 1, 'host': host, 'directory_url': 'https://172.30.100.2:14000/dir',
                 'contact_email': 'admin@example.test', 'api_roots_file': stage + '/api-root.pem',
                 'certificate_roots_file': stage + '/issuing-root.pem',
                 'account_backup_directory': stage + '/account-registered',
                 'http01_route_file': control + '/http01.caddy',
                 'forward_address': '172.30.100.1', 'forward_port': 18441}
        self.assertTrue(valid_ready(ready, host, control))
        for key, value in [('version', True), ('host', 'different.devices.example.test'),
                           ('directory_url', 'https://unrelated.example/dir'),
                           ('directory_url', 'https://172.30.100.3:14000/dir'),
                           ('directory_url', 'https://user@172.30.100.2:14000/dir'),
                           ('contact_email', 'different@example.test'),
                           ('forward_address', '127.0.0.1'), ('forward_address', '172.30.100.2'),
                           ('forward_port', True), ('forward_port', 443),
                           ('api_roots_file', '/etc/unrelated.pem'),
                           ('certificate_roots_file', stage + '/../issuing-root.pem'),
                           ('account_backup_directory', stage + '/account'),
                           ('http01_route_file', '/tmp/unrelated/http01.caddy')]:
            with self.subTest(field=key):
                self.assertFalse(valid_ready({**ready, key: value}, host, control))
        for invalid in (None, [], {}, {**ready, 'extra': True}):
            self.assertFalse(valid_ready(invalid, host, control))
        for invalid in (None, control + '/', control + '/..', '/relative/witness', 'relative/witness'):
            self.assertFalse(valid_ready(ready, host, invalid))


if __name__ == '__main__':
    unittest.main()
