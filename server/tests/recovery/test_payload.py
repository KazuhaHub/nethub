import copy
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import payload


class MemberAdmission(unittest.TestCase):
    def test_paths_links_duplicates_permissions_and_foreign_owners_refused(self):
        root = tarfile.TarInfo('tmp/owned-recovery')
        root.type, root.mode = tarfile.DIRTYPE, 0o700
        file = tarfile.TarInfo('tmp/owned-recovery/current-key')
        file.mode, file.size = 0o600, 3
        roots = [PurePosixPath(root.name)]
        payload.validate_members([root, file], roots)
        for field, value in [('name', '/tmp/owned-recovery/key'), ('name', 'tmp/owned-recovery/../key'),
                             ('name', 'tmp/other/key'), ('name', 'tmp/owned-recovery\\key'),
                             ('type', tarfile.SYMTYPE), ('type', tarfile.LNKTYPE),
                             ('type', tarfile.FIFOTYPE), ('uid', 99), ('mode', 0o666),
                             ('size', -1), ('pax_headers', {'path': 'elsewhere'})]:
            candidate = copy.deepcopy(file)
            setattr(candidate, field, value)
            with self.subTest(field=field, value=value), self.assertRaises(payload.PayloadError):
                payload.validate_members([root, candidate], roots)
        with self.assertRaises(payload.PayloadError):
            payload.validate_members([root, file, file], roots)
        with self.assertRaises(payload.PayloadError):
            payload.validate_members([file], roots)


@unittest.skipUnless(os.name == 'posix', 'actual POSIX file identity and ownership required')
class ActualPayloadRecovery(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='nethub-recovery-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / 'current'
        self.root.mkdir(mode=0o700)
        self.file = self.root / 'retained-key'
        self.file.write_bytes(b'private fixture material\n')
        self.file.chmod(0o600)
        self.archive = self.base / 'recovery.tar'
        owners = patch.object(payload, 'OWNERS', {os.getuid(), os.getgid()})
        owners.start()
        self.addCleanup(owners.stop)
        self.receipt = payload.pack([self.root, self.file], self.archive)

    def test_restore_exact_bytes_metadata_and_empty_volume_root(self):
        expected = self.file.read_bytes()
        # Remove only this test's explicitly owned directory after resolving it.
        self.assertEqual(self.root.parent, self.base)
        shutil.rmtree(self.root)
        self.root.mkdir(mode=0o755)
        value = payload.restore(self.archive, [self.root], self.receipt['sha256'], self.receipt['inventory_sha256'])
        self.assertTrue(value['inventory_verified'])
        self.assertEqual(self.file.read_bytes(), expected)
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)

    def test_existing_target_refused_before_overwrite(self):
        expected = self.file.read_bytes()
        with self.assertRaises(payload.PayloadError):
            payload.restore(self.archive, [self.root], self.receipt['sha256'], self.receipt['inventory_sha256'])
        self.assertEqual(self.file.read_bytes(), expected)

    def test_corruption_refused_before_any_target_write(self):
        missing = self.base / 'absent'
        data = self.archive.read_bytes()
        changed = self.base / 'corrupt.tar'
        changed.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        with self.assertRaises(payload.PayloadError):
            payload.restore(changed, [missing], self.receipt['sha256'], self.receipt['inventory_sha256'])
        self.assertFalse(missing.exists())

    def test_source_link_refused(self):
        link = self.base / 'linked-key'
        link.symlink_to(self.file)
        with self.assertRaises(payload.PayloadError):
            payload.pack([link], self.base / 'linked.tar')


if __name__ == '__main__':
    unittest.main()
