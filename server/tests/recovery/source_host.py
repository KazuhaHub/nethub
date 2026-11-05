"""Prepare the original cold-recovery host inside a fresh owned Linux guest.

This is preparation for the combined cold-host driver. It does not yet restore
an issuer, start its timers, enroll a client or establish recovery acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

from image_archive import inspect_archive
from linux_guest import LinuxGuest, RecoveryError, sha256


ROLES = {'runtime', 'postgres', 'caddy', 'frps', 'backup'}
UNITS = ('nethub-gui-issuer.service', 'nethub-gui-issuer.timer',
         'nethub-http01-cleanup.service', 'nethub-http01-cleanup.timer')
SOURCE = '/srv/nethub-source'
HELPER = '/usr/local/libexec/nethub'


def validate_selection(tags, inspected):
    if (not isinstance(tags, dict) or set(tags) != ROLES
            or any(not isinstance(value, str)
                   or re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_./:-]{0,255}', value) is None
                   for value in tags.values())
            or len(set(tags.values())) != len(ROLES) or set(inspected) != set(tags.values())):
        raise RecoveryError('Exactly five previously tested recovery image roles required')


class SourceHost:
    def __init__(self, guest, repository):
        if (type(guest) is not LinuxGuest or guest.process is None
                or guest.process.poll() is not None):
            raise RecoveryError('Live owned hosted Linux guest required')
        self.guest, self.repository = guest, Path(repository).resolve(strict=True)
        self.head = os.environ.get('NETHUB_SOURCE_HEAD', '')
        if re.fullmatch('[a-f0-9]{40}', self.head) is None:
            raise RecoveryError('Exact recovery source head required')
        self.work = guest.directory / 'source-bootstrap'
        self.work.mkdir(mode=0o700)
        self.counter = 0

    def command(self, args, label, *, output=None, timeout=60):
        self.counter += 1
        try:
            result = subprocess.run(args, cwd=self.repository,
                                    stdout=output if output is not None else subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise RecoveryError(label + ' unavailable or timed out') from None
        (self.work / f'step-{self.counter}.log').write_bytes(
            (result.stdout if output is None else b'') + result.stderr)
        if result.returncode:
            raise RecoveryError(label + ' failed')
        return result.stdout

    def remote(self, args, label, *, timeout=60):
        return self.guest.ssh(shlex.join(args) + '\n', label, timeout=timeout)

    def send_module(self, name):
        destination = self.work / name
        destination.write_bytes(self.command(['git', 'show', self.head + ':server/tests/recovery/' + name],
                                            'Exact recovery helper source'))
        destination.chmod(0o600)
        return self.guest.send(destination, name)

    def bootstrap(self, images, tags):
        # The caller's producer gate must already bind the archive to this exact
        # successful CI source. Content verification here is a separate check.
        if self.command(['git', 'rev-parse', 'HEAD'], 'Recovery source identity').decode().strip() != self.head:
            raise RecoveryError('Recovery checkout differs from the selected source')
        inspected = inspect_archive(Path(images))
        validate_selection(tags, inspected)
        prepared = self.guest.prepare()
        self.guest.ssh('umask 077\nmkdir /root/nethub-recovery\n', 'New private source transfer namespace')
        remote_images = self.guest.send(images, 'images.tar')
        self.remote(['docker', 'load', '-i', remote_images], 'Original guest image load', timeout=180)
        verifier = self.send_module('image_archive.py')
        exported = '/root/nethub-recovery/reloaded-images.tar'
        self.remote(['docker', 'image', 'save', '-o', exported, *sorted(tags.values())],
                    'Original guest loaded image export', timeout=180)
        actual = json.loads(self.remote(['python3', verifier, exported],
                                       'Original guest complete image verification', timeout=180))
        if actual != inspected:
            raise RecoveryError('Original guest image configuration or layers differ')

        source = self.work / 'source.tar'
        with source.open('xb') as output:
            self.command(['git', '-c', 'core.autocrlf=false', '-c', 'tar.umask=0022',
                          'archive', '--format=tar', self.head],
                         'Exact tracked recovery source export', output=output)
        source.chmod(0o600)
        remote_source = self.guest.send(source, 'source.tar')
        extractor = self.send_module('source_archive.py')
        extracted = json.loads(self.remote(['python3', extractor, remote_source, SOURCE, sha256(source), self.head],
                                          'New original guest source extraction'))
        if extracted.get('source_archive_verified') is not True:
            raise RecoveryError('Original guest source extraction was not confirmed')

        self.guest.ssh('test ! -e ' + HELPER + '\nmkdir -p /usr/local/libexec\n',
                       'Unused original guest helper location')
        container = self.remote(['docker', 'create', '--network', 'none', '--read-only',
            '--label', 'org.nethub.recovery-source=' + self.head, tags['runtime']],
            'Tested helper extraction container').decode().strip()
        if re.fullmatch('[a-f0-9]{64}', container) is None:
            raise RecoveryError('Owned helper extraction container identity refused')
        try:
            self.remote(['docker', 'cp', container + ':/nethub', HELPER], 'Tested original host helper extraction')
            self.remote(['chown', '0:0', HELPER], 'Original host helper ownership')
            self.remote(['chmod', '0555', HELPER], 'Original host helper mode')
        finally:
            self.remote(['docker', 'rm', container], 'Owned helper extraction container removal')

        for unit in UNITS:
            destination = '/etc/systemd/system/' + unit
            self.guest.ssh('test ! -e ' + shlex.quote(destination) + '\n',
                           'Unused persistent issuer unit location')
            self.remote(['install', '-o', 'root', '-g', 'root', '-m', '0644',
                         SOURCE + '/deploy/systemd/' + unit, destination], 'Original persistent issuer unit installation')
            expected = hashlib.sha256(self.command(['git', 'show',
                self.head + ':deploy/systemd/' + unit], 'Exact persistent issuer unit source')).hexdigest()
            actual = self.remote(['sha256sum', destination], 'Persistent issuer unit readback').split()[0].decode()
            if actual != expected:
                raise RecoveryError('Original persistent issuer unit bytes differ')
        self.remote(['systemctl', 'daemon-reload'], 'Original persistent unit loading')
        for unit in UNITS:
            for prop, expected in [('LoadState', 'loaded'), ('FragmentPath', '/etc/systemd/system/' + unit),
                                   ('DropInPaths', ''), ('ActiveState', 'inactive'),
                                   ('UnitFileState', 'disabled' if unit.endswith('.timer') else 'static')]:
                value = self.remote(['systemctl', 'show', unit, '--property=' + prop, '--value'],
                                    'Inactive original persistent unit verification').decode().strip()
                if value != expected:
                    raise RecoveryError('Original persistent unit binding or inactive intent differs')
        return {'host': prepared, 'same_tested_image_content': True,
                'exact_tracked_source': True, 'exact_stock_persistent_units_loaded_inactive': True,
                'issuer_restored_or_recovery_accepted': False}
