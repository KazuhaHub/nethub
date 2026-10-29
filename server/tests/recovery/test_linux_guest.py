import copy
import unittest

from linux_guest import (IMAGE, IMAGE_SHA256, SIGNER, RecoveryError, cloud_config,
                         validate_identity, verify_checksum_list, verify_signer)


class SourceAuthentication(unittest.TestCase):
    def test_ambiguous_or_replaced_image_refused(self):
        expected = f'{IMAGE_SHA256} *{IMAGE}\n'.encode()
        verify_checksum_list(expected)
        for value in (expected + expected, expected.replace(IMAGE_SHA256.encode(), b'0' * 64),
                      expected.replace(IMAGE.encode(), b'other.img'), b'\xff'):
            with self.subTest(value=value[:16]), self.assertRaises(RecoveryError):
                verify_checksum_list(value)

    def test_signed_status_requires_exact_cloud_authority(self):
        valid = f'[GNUPG:] VALIDSIG {SIGNER} 2026-10-17 1792195200 0 4 0 1 10 00 {SIGNER}\n'.encode()
        verify_signer(valid)
        for value in (valid + valid, valid.replace(SIGNER.encode(), b'0' * 40),
                      b'[GNUPG:] GOODSIG 7DB87C81 UEC\n', b'[GNUPG:] VALIDSIG \n', b'\xff'):
            with self.subTest(value=value[:16]), self.assertRaises(RecoveryError):
                verify_signer(value)


class DistinctHostAdmission(unittest.TestCase):
    def setUp(self):
        self.host_machine = '0' * 32
        self.host_boot = '00000000-0000-0000-0000-000000000000'
        self.target = {'machine_id': '1' * 32, 'boot_id': '11111111-1111-1111-1111-111111111111',
                       'os_id': 'ubuntu', 'os_version': '24.04', 'empty_deployment': True,
                       'empty_database': True, 'docker_version': '28.2.2', 'compose_version': '2.37.1',
                       'containers': [], 'volumes': []}

    def test_shared_identity_or_existing_state_refused(self):
        validate_identity(self.target, self.host_machine, self.host_boot)
        changes = {'machine_id': self.host_machine, 'boot_id': self.host_boot,
                   'os_version': '22.04', 'empty_deployment': False, 'empty_database': False,
                   'containers': ['existing'], 'volumes': ['existing'], 'docker_version': 'unknown',
                   'compose_version': 'unknown'}
        for key, value in changes.items():
            target = copy.deepcopy(self.target)
            target[key] = value
            with self.subTest(key=key), self.assertRaises(RecoveryError):
                validate_identity(target, self.host_machine, self.host_boot)

    def test_password_login_disabled_and_host_key_prebound(self):
        value = cloud_config('client public', 'host private', 'host public')
        self.assertIs(value['ssh_pwauth'], False)
        self.assertIs(value['users'][0]['lock_passwd'], True)
        self.assertEqual(value['users'][0]['ssh_authorized_keys'], ['client public'])
        self.assertEqual(value['ssh_keys']['ed25519_public'], 'host public')


if __name__ == '__main__':
    unittest.main()
