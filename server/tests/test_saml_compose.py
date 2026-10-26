"""Check the independent SAML fixture's credential and container boundaries."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('saml_compose', Path(__file__).with_name('saml-compose.py'))
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)


class SAMLFixtureBoundaries(unittest.TestCase):
    def test_realm_has_only_disposable_fixed_users_and_closed_self_registration(self):
        realm = suite.realm_import('a' * 64)
        self.assertFalse(realm['registrationAllowed'])
        self.assertFalse(realm['resetPasswordAllowed'])
        self.assertEqual([user['username'] for user in realm['users']], ['alice', 'bob', 'mailbox'])
        self.assertFalse(realm['users'][0]['emailVerified'])
        for user in realm['users']:
            self.assertEqual(user['credentials'], [{'type': 'password', 'value': 'a' * 64, 'temporary': False}])
        for invalid in ('', 'x' * 64, 'a' * 63, 'a' * 65, 'a' * 64 + '\n', None):
            with self.subTest(invalid=invalid), self.assertRaises((suite.Failure, TypeError)):
                suite.realm_import(invalid)

    def test_idp_has_no_published_ports_or_host_privilege(self):
        service = suite.idp_service('172.30.87.9', Path('/owned/realm.json'), 'b' * 64)
        self.assertEqual(service['image'], suite.IDP_IMAGE)
        self.assertRegex(service['image'], r'^quay.io/keycloak/keycloak:26\.8\.1@sha256:[a-f0-9]{64}$')
        for forbidden in ('ports', 'privileged', 'network_mode', 'pid', 'devices', 'cap_add'):
            self.assertNotIn(forbidden, service)
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertEqual(service['security_opt'], ['no-new-privileges:true'])
        self.assertEqual(service['user'], '1000:0')
        self.assertEqual(service['mem_limit'], '1024m')
        self.assertTrue(service['volumes'][0]['read_only'])
        self.assertIn('--hostname=https://saml.test', service['command'])
        self.assertIn('--import-realm', service['command'])
        self.assertEqual(service['logging']['options'], {'max-size': '5m', 'max-file': '2'})


if __name__ == '__main__':
    unittest.main()
