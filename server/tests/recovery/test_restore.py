"""Recovery failures expose fixed source categories without private file names."""
import os
import json
from pathlib import Path
import tempfile
import unittest

from payload import PayloadError

if os.name == 'posix':
    from restore import Restore
    from linux_guest import RecoveryError


@unittest.skipUnless(os.name == 'posix', 'the restoration driver requires Linux flock')
class ClosedPayloadFailure(unittest.TestCase):
    def test_original_login_opens_only_retained_native_and_witness_identities(self):
        self.check_open('200')

    def test_original_login_refusal_exports_only_http_status(self):
        with self.assertRaises(RecoveryError) as caught:
            self.check_open('409')
        self.assertEqual(str(caught.exception), 'Explicit source grant on recovered host returned HTTP 409')

    def check_open(self, status):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = object.__new__(Restore)
            fixture.stage = fixture.work = Path(temporary)
            fixture.port = 443
            (fixture.stage / 'login-response.json').write_text(json.dumps({'user': {'id': 'original'}}))
            identifiers = ['00000000-0000-4000-8000-00000000000' + str(i) for i in range(3)]
            opened = []
            def command(args, label):
                if label.startswith('Original administrator login'):
                    return json.dumps({'user': {'id': 'original', 'role': 'admin'},
                                       'csrf_token': 'private-token'}).encode()
                if label == 'Restored administrator inventory':
                    return json.dumps({'items': [{'id': value, 'revoked': i == 2}
                                                for i, value in enumerate(identifiers)]}).encode()
                self.assertEqual(label, 'Explicit source grant on recovered host')
                self.assertNotIn('--fail', args)
                self.assertIn('--output', args)
                opened.append(args[-1].split('/')[-2])
                return status.encode()
            fixture.command = command
            fixture.original_login(identifiers[:2])
            self.assertEqual(opened, identifiers[:2])
            self.assertEqual(fixture.restored_device_ids, set(identifiers))

    def test_scoped_permission_and_unknown_error_do_not_export_private_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = object.__new__(Restore)
            fixture.stage = Path(temporary).resolve()
            volume = fixture.stage / 'private-volume'
            fixture.volumes = {'caddy-config': volume}
            error = PayloadError('source_permissions', path=volume / 'private-key', mode=0o1777)
            value = fixture.payload_diagnostic(error)
            self.assertEqual(value, {'version': 1, 'reason': 'source_permissions',
                                     'source_scope': 'caddy_config', 'observed_mode': '1777'})
            self.assertNotIn('private', str(value))
            unknown = PayloadError('private response and path', path=volume, mode=99999)
            value = fixture.payload_diagnostic(unknown)
            self.assertEqual(value['reason'], 'other')
            self.assertEqual(value['observed_mode'], 'unknown')
            self.assertNotIn('private', str(value))


if __name__ == '__main__':
    unittest.main()
