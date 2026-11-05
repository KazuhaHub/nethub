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
from source_host import SourceHost, configure_profile, validate_selection
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
    def test_proof_reads_refuse_mutations_and_unprepared_endpoints_before_ssh(self):
        source = object.__new__(SourceHost)
        source.stack_started, source.host_prepared = True, False
        for query in (None, 'DROP TABLE devices', 'SELECT 1; DELETE FROM devices',
                      'BEGIN; SELECT 1', 'UPDATE devices SET revoked=true'):
            with self.subTest(query=query), self.assertRaises(RecoveryError):
                source.query(query)
        with self.assertRaises(RecoveryError):
            source.entry_address()

    def test_unowned_or_missing_guest_refused_before_any_command(self):
        with self.assertRaises(RecoveryError):
            SourceHost(None, Path(__file__).parent)

    def test_unprepared_or_already_started_source_refused_before_initialization(self):
        source = object.__new__(SourceHost)
        for prepared, started in ((False, False), (True, True)):
            source.bootstrap_completed, source.stack_started = prepared, started
            with self.subTest(prepared=prepared, started=started), self.assertRaises(RecoveryError):
                source.initialize_stack()
        for started, configured in ((False, False), (True, True)):
            source.stack_started, source.issuer_configured = started, configured
            with self.subTest(started=started, configured=configured), self.assertRaises(RecoveryError):
                source.configure_issuer({}, 'abcdefgh.devices.example.test')

    def test_image_selection_preserves_generated_security_settings_and_input(self):
        tags = {role: 'owned/' + role + ':source' for role in ('runtime', 'postgres', 'caddy', 'frps', 'backup')}
        services = {name: {} for name in ('postgres', 'migrate', 'nethub-web', 'nethub-authz', 'frps', 'caddy')}
        services['nethub-authz'] = {'command': ['authz', '--trusted-proxy', '172.30.87.2/32'],
                                    'ports': [{'host_ip': '127.0.0.1', 'published': 9000, 'target': 9000}],
                                    'networks': {'edge': {'ipv4_address': '172.30.87.4'}}}
        original = {'services': services, 'networks': {'edge': {'ipam': {'config': [{'subnet': '172.30.87.0/24'}]}}}}
        retained = copy.deepcopy(original)
        caddy = '{$NETHUB_CONSOLE_HOST} {\n    respond /healthz 404\n}\n'
        selected, private_caddy = configure_profile(original, tags, caddy)
        self.assertEqual(original, retained)
        self.assertEqual(selected['networks'], retained['networks'])
        for name, service in retained['services'].items():
            self.assertEqual({k: v for k, v in selected['services'][name].items() if k != 'image'}, service)
        self.assertEqual(private_caddy, 'https://console.example.com {\n    tls internal\n    respond /healthz 404\n}\n')
        for changed in ({'services': {**services, 'foreign-service': {}}},
                        {'services': {k: v for k, v in services.items() if k != 'nethub-authz'}}, {}):
            with self.subTest(profile=changed), self.assertRaises(RecoveryError):
                configure_profile(changed, tags, caddy)
        for changed in ('', caddy + caddy):
            with self.subTest(caddy=changed), self.assertRaises(RecoveryError):
                configure_profile(original, tags, changed)

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
