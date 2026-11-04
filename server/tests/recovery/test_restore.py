"""Recovery failures expose fixed source categories without private file names."""
import os
from pathlib import Path
import tempfile
import unittest

from payload import PayloadError

if os.name == 'posix':
    from restore import Restore


@unittest.skipUnless(os.name == 'posix', 'the restoration driver requires Linux flock')
class ClosedPayloadFailure(unittest.TestCase):
    def test_scoped_permission_and_unknown_error_do_not_export_private_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = object.__new__(Restore)
            fixture.stage = Path(temporary).resolve()
            volume = fixture.stage / 'private-volume'
            fixture.volumes = {'caddy-data': volume}
            error = PayloadError('source_permissions', path=volume / 'private-key', mode=0o777)
            value = fixture.payload_diagnostic(error)
            self.assertEqual(value, {'version': 1, 'reason': 'source_permissions',
                                     'source_scope': 'caddy_data', 'observed_mode': '0777'})
            self.assertNotIn('private', str(value))
            unknown = PayloadError('private response and path', path=volume, mode=99999)
            value = fixture.payload_diagnostic(unknown)
            self.assertEqual(value['reason'], 'other')
            self.assertEqual(value['observed_mode'], 'unknown')
            self.assertNotIn('private', str(value))


if __name__ == '__main__':
    unittest.main()
