"""Check exact Git format and refuse unsafe source before destination mutation."""
import copy
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

import source_archive
from source_host import SourceHost, validate_selection
from linux_guest import RecoveryError


HEAD = '1' * 40


class SourceArchiveAdmission(unittest.TestCase):
    def archive(self, directory, entries, *, head=HEAD):
        archive = directory / 'source.tar'
        with tarfile.open(archive, 'w', format=tarfile.PAX_FORMAT, pax_headers={'comment': head}) as bundle:
            for entry in entries:
                entry = copy.copy(entry)
                bundle.addfile(entry, io.BytesIO(b'x' * entry.size) if entry.isfile() else None)
        return archive

    def file(self, name='deploy/helper'):
        value = tarfile.TarInfo(name)
        value.mode, value.size = 0o644, 1
        return value

    def extract(self, archive, destination, *, head=HEAD, checksum=None):
        return source_archive.extract(archive, destination, checksum or hashlib.sha256(archive.read_bytes()).hexdigest(), head)

    def test_actual_git_archive_retains_exact_shipped_unit_bytes(self):
        repository = Path(__file__).resolve().parents[3]
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repository, text=True).strip()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = root / 'source.tar'
            with archive.open('xb') as stream:
                subprocess.run(['git', '-c', 'core.autocrlf=false', '-c', 'tar.umask=0022',
                                'archive', '--format=tar', head],
                               cwd=repository, stdout=stream, check=True)
            result = self.extract(archive, root / 'source', head=head)
            self.assertTrue(result['source_archive_verified'])
            for unit in ('nethub-gui-issuer.service', 'nethub-gui-issuer.timer',
                         'nethub-http01-cleanup.service', 'nethub-http01-cleanup.timer'):
                expected = subprocess.check_output(['git', 'show', head + ':deploy/systemd/' + unit], cwd=repository)
                self.assertEqual((root / 'source/deploy/systemd' / unit).read_bytes(), expected)

    def test_unsafe_members_refused_before_creating_destination(self):
        cases = [('name', '../elsewhere'), ('name', '/etc/elsewhere'), ('name', '.'),
                 ('name', 'deploy/../elsewhere'), ('name', 'deploy\\elsewhere'),
                 ('name', 'deploy/line\nend'), ('mode', 0o666), ('mode', 0o4755),
                 ('type', tarfile.SYMTYPE), ('type', tarfile.LNKTYPE),
                 ('type', tarfile.FIFOTYPE), ('type', tarfile.CONTTYPE),
                 ('pax_headers', {'linkpath': '/etc/elsewhere'})]
        for field, value in cases:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                entry = self.file()
                setattr(entry, field, value)
                archive = self.archive(root, [entry])
                destination = root / 'source'
                with self.assertRaises(ValueError):
                    self.extract(archive, destination)
                self.assertFalse(destination.exists())

    def test_duplicates_conflicting_parents_and_identity_refused_before_writes(self):
        for entries in ([self.file(), self.file()], [self.file('deploy'), self.file('deploy/helper')],
                        [self.file(), self.file('deploy/helper/')]):
            with self.subTest(entries=[e.name for e in entries]), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve();archive = self.archive(root, entries)
                with self.assertRaises(ValueError):
                    self.extract(archive, root / 'source')
                self.assertFalse((root / 'source').exists())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve();archive = self.archive(root, [self.file()])
            for kwargs in ({'head': '2' * 40}, {'checksum': '0' * 64}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    self.extract(archive, root / 'source', **kwargs)
                self.assertFalse((root / 'source').exists())

    def test_existing_destination_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve();archive = self.archive(root, [self.file()])
            destination = root / 'source';destination.mkdir()
            retained = destination / 'retained';retained.write_bytes(b'original')
            with self.assertRaises(ValueError):
                self.extract(archive, destination)
            self.assertEqual(retained.read_bytes(), b'original')


class SourceHostAdmission(unittest.TestCase):
    def test_unowned_or_missing_guest_refused_before_any_command(self):
        with self.assertRaises(RecoveryError):
            SourceHost(None, Path(__file__).parent)

    def test_five_distinct_tested_roles_cannot_be_omitted_substituted_or_aliased(self):
        tags = {role: 'owned/' + role + ':source' for role in ('runtime', 'postgres', 'caddy', 'frps', 'backup')}
        selected = dict.fromkeys(tags.values())
        validate_selection(tags, selected)
        for changed in ({**tags, 'runtime': tags['backup']}, {**tags, 'runtime': '--privileged'},
                        {**tags, 'foreign': 'owned/foreign:source'}, {k: v for k, v in tags.items() if k != 'backup'}):
            with self.subTest(tags=changed), self.assertRaises(RecoveryError):
                validate_selection(changed, selected)
        for changed in ({**selected, 'owned/foreign:source': None},
                        {key: value for key, value in selected.items() if key != tags['backup']}):
            with self.subTest(selection=changed), self.assertRaises(RecoveryError):
                validate_selection(tags, changed)


if __name__ == '__main__':
    unittest.main()
