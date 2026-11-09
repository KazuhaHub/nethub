"""Exercise private export refusal against actual owned Linux files."""
import hashlib
import io
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

import checkpoint_transfer as transfer


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'actual root-owned Linux files required')
class PrivateCheckpointExport(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='nethub-export-unit-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / 'checkpoint.json'
        self.content = b'private fixture content\n'
        self.path.write_bytes(self.content)
        self.path.chmod(0o600)
        for name, value in (('TRANSFER', str(self.root)), ('__file__', str(self.root / 'export.py'))):
            replacement = patch.object(transfer, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)

    def read(self, stream=None):
        stream = io.BytesIO() if stream is None else stream
        with patch.object(transfer.sys, 'stdout', SimpleNamespace(buffer=stream)):
            result = transfer.export('read', self.path.name)
        self.assertIsNone(result)
        return stream.getvalue()

    def test_complete_export_matches_info_and_keeps_original_bytes_and_permissions(self):
        expected = {'bytes': len(self.content), 'sha256': hashlib.sha256(self.content).hexdigest()}
        self.assertEqual(transfer.export('info', self.path.name), expected)
        self.assertEqual(self.read(), self.content)
        self.assertEqual(self.path.read_bytes(), self.content)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_unknown_names_actions_permissions_links_and_size_are_refused(self):
        for action, name in (('info', '../checkpoint.json'), ('read', 'unrelated-key'),
                             ('remove', 'checkpoint.json')):
            with self.subTest(action=action, name=name), self.assertRaises(ValueError):
                transfer.export(action, name)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.read()
        self.path.chmod(0o600)
        alias = self.root / 'alias'
        os.link(self.path, alias)
        with self.assertRaises(ValueError):
            self.read()
        alias.unlink()
        self.path.rename(alias)
        self.path.symlink_to(alias)
        with self.assertRaises(OSError):
            self.read()
        self.path.unlink()
        alias.rename(self.path)
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            self.read()
        self.root.chmod(0o700)
        password = self.root / 'admin-password'
        password.write_bytes(b'x' * 1025)
        password.chmod(0o600)
        with self.assertRaises(ValueError):
            transfer.export('info', password.name)
        self.assertEqual(self.path.read_bytes(), self.content)

    def test_actual_growth_or_replacement_during_streaming_never_completes(self):
        path = self.path
        for change in ('grow', 'replace'):
            with self.subTest(change=change):
                path.write_bytes(b'x' * (128 * 1024))
                path.chmod(0o600)

                class ChangedStream(io.BytesIO):
                    changed = False

                    def write(stream, data):
                        if not stream.changed:
                            stream.changed = True
                            if change == 'grow':
                                with path.open('ab') as output:
                                    output.write(b'y')
                            else:
                                path.rename(path.with_suffix('.retained'))
                                path.write_bytes(b'x' * (128 * 1024))
                                path.chmod(0o600)
                        return super().write(data)

                with self.assertRaises(ValueError):
                    self.read(ChangedStream())


if __name__ == '__main__':
    unittest.main()
