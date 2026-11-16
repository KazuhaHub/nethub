"""Nonce-bound bad-template fixture; no production or package publication use."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

from wan_probe import boundary


TEMPLATE = 'usr/local/opnsense/service/templates/OPNsense/NetHubAgent/frpc.toml.j2'
BAD_PREFIX = b'nethub_fixture_unknown_configuration_key = true\n'


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


class Fixture:
    """Filesystem helpers are testable separately from the mandatory CLI boundary."""
    def __init__(self, root=Path('/'), *, box=None, send=None, runner=subprocess.run):
        self.root = Path(root)
        if self.root.absolute() != self.root.resolve():
            raise ValueError('Aliased fixture root refused')
        self.state = self.root / 'var/db/nethub-agent'
        self.directory = self.root / 'root/nethub-ci/reconcile-audit-fixture'
        self.template = self.root / TEMPLATE
        self.source = self.root / 'root/nethub-ci/source/agents/opnsense/plugin/src' / TEMPLATE
        if box is None:
            sys.path.insert(0, str(self.root / 'usr/local/opnsense/scripts/nethub-agent'))
            from reconcile_audit import Outbox, report_events
            box, send = Outbox, report_events
        self.box, self.send, self.run = box, send, runner

    @staticmethod
    def regular(path, *, private=None, maximum=65536):
        if path.resolve() != path:
            raise ValueError('Aliased fixture file refused')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or not 0 < info.st_size <= maximum
                    or private is True and stat.S_IMODE(info.st_mode) != 0o600
                    or private is False and info.st_mode & 0o022):
                raise ValueError('Unsafe fixture file refused')
            raw = source.read(maximum + 1)
            if len(raw) > maximum:
                raise ValueError('Oversized fixture file refused')
        return raw, stat.S_IMODE(info.st_mode)

    @staticmethod
    def atomic(path, raw, mode=0o600):
        temporary = path.with_name('.audit-fixture-' + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            with os.fdopen(descriptor, 'wb') as target:
                os.fchmod(target.fileno(), mode)
                target.write(raw)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    @contextmanager
    def locked(self):
        if self.state.resolve() != self.state:
            raise ValueError('Aliased fixture state refused')
        parent = self.state.lstat()
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ValueError('Private native state required')
        path = self.state / 'reconcile.lock'
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_size != 0 or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError('Original native lock required')
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = path.lstat()
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('Native lock changed')
            yield
        finally:
            os.close(descriptor)

    def identity(self):
        model = ET.parse(self.root / 'conf/config.xml').find('OPNsense/NetHubAgent')
        if model is None or model.findtext('enabled') != '1':
            raise ValueError('Enabled native enrollment required')
        device = model.findtext('device_id')
        if not isinstance(device, str) or str(uuid.UUID(device)) != device:
            raise ValueError('Canonical enrolled device required')
        return model, device

    def _pending(self):
        _model, device = self.identity()
        box = self.box(self.state, device)
        with box.opened() as directory:
            value = box.load(directory)
        if value['overflow'] is not None or len(value['events']) > 8:
            raise ValueError('Single bounded fixture batch required')
        return {'device_id': device, 'events': value['events']}

    def pending(self):
        with self.locked():
            return self._pending()

    def journal(self):
        parent = self.directory.lstat()
        if (self.directory.resolve() != self.directory or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700):
            raise ValueError('Private original fixture directory required')
        raw, _mode = self.regular(self.directory / 'journal.json', private=True, maximum=4096)
        value = json.loads(raw)
        if (set(value) != {'version', 'original_sha256', 'invalid_sha256', 'mode', 'restored'}
                or type(value['version']) is not int or value['version'] != 1
                or type(value['restored']) is not bool or type(value['mode']) is not int
                or value['mode'] & ~0o777 or value['mode'] & 0o022):
            raise ValueError('Original fixture journal required')
        return value

    def _arm(self):
        if self._pending()['events']:
            raise ValueError('Existing retained failures must not be mixed with the fixture')
        original, mode = self.regular(self.template, private=False)
        source, _ = self.regular(self.source)
        if original != source:
            raise ValueError('Installed template differs from the admitted source')
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        invalid = BAD_PREFIX + original
        value = {'version': 1, 'original_sha256': hashlib.sha256(original).hexdigest(),
                 'invalid_sha256': hashlib.sha256(invalid).hexdigest(), 'mode': mode, 'restored': False}
        self.atomic(self.directory / 'template.original', original)
        # Retain intent before changing the installed template. Never re-arm.
        self.atomic(self.directory / 'journal.json', encoded(value))
        self.atomic(self.template, invalid, mode)

    def _restore(self):
        value = self.journal()
        original, _ = self.regular(self.directory / 'template.original', private=True)
        current, mode = self.regular(self.template, private=False)
        if hashlib.sha256(original).hexdigest() != value['original_sha256'] or mode != value['mode']:
            raise ValueError('Original fixture template changed')
        digest = hashlib.sha256(current).hexdigest()
        if digest not in (value['original_sha256'], value['invalid_sha256']):
            raise ValueError('Unrelated template change must not be overwritten')
        if value['restored'] and digest != value['original_sha256']:
            raise ValueError('Restored fixture template changed')
        if digest != value['original_sha256']:
            self.atomic(self.template, original, value['mode'])
        if not value['restored']:
            value['restored'] = True
            self.atomic(self.directory / 'journal.json', encoded(value))
        return {'restored': True}

    def restore(self):
        with self.locked():
            return self._restore()

    def _capture(self):
        if not self.journal()['restored']:
            raise ValueError('Restore the original template before event delivery')
        value = self._pending()
        if len(value['events']) != 1 or any(e['kind'] != 'reconcile_failed' or e['count'] != 1 for e in value['events']):
            raise ValueError('Genuine ordinary reconcile failures required')
        target = self.directory / 'captured.json'
        with target.open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(encoded(value))
            output.flush()
            os.fsync(output.fileno())
        return value

    def cli(self, label):
        # The parent holds the actual persistent mutation lock throughout this
        # normal CLI invocation, just as the package's lockf/configd wrapper does.
        result = self.run(['/usr/local/bin/python3.13',
            str(self.root / 'usr/local/opnsense/scripts/nethub-agent/agentctl.py'),
            '--locked', 'reconcile'], capture_output=True, timeout=45)
        if len(result.stdout) > 8192 or len(result.stderr) > 16384:
            raise ValueError('Bounded native CLI outcome required')
        if label not in ('failure', 'recovery'):
            raise ValueError('Known native CLI stage required')
        self.atomic(self.directory / (label + '-cli-private.log'), result.stdout + b'\n' + result.stderr)
        return result.returncode, json.loads(result.stdout)

    def failure(self):
        with self.locked():
            first = None
            try:
                self._arm()
                status, result = self.cli('failure')
                if (status != 1 or result.get('success') is not False or result.get('audit_recorded') is not True
                        or result.get('action') != 'error' or result.get('message') !=
                        'frpc rejected the candidate configuration; live configuration was retained'):
                    raise ValueError('Actual candidate refusal and retained audit event required')
            except Exception as error:
                first = error
            try:
                # An interrupted arm can already have replaced the template.
                # Restore its journal even when the CLI was never reached.
                if (self.directory / 'journal.json').exists():
                    self._restore()
            except Exception:
                # The original operation stays failed. Keep both stages in a
                # private fixed diagnostic without replacing it with child text.
                self.atomic(self.directory / 'restore-refused.json', encoded({
                    'first_failure_retained': first is not None, 'restore_refused': True}))
                raise ValueError('Fixture restoration refused; retain the original attempt') from None
            if first is not None:
                raise first
            captured = self._capture()
            return dict(captured, candidate_refused=True, template_restored=True, native_cli_exit=status)

    def recover(self):
        with self.locked():
            if not self.journal()['restored'] or self._pending()['events']:
                raise ValueError('Original template and normal acknowledgement required before recovery')
            intent = self.directory / 'recovery-requested'
            with intent.open('xb') as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(b'One explicit normal reconcile after acknowledgement\n')
                output.flush()
                os.fsync(output.fileno())
            status, result = self.cli('recovery')
            if status != 0 or result.get('success') is not True or result.get('action') != 'unchanged':
                raise ValueError('Unchanged running configuration required after fixture restoration')
            return {'recovered_without_restart': True, 'native_cli_exit': status}

    def replay(self):
        with self.locked():
            if self._pending()['events']:
                raise ValueError('Normal reporting must acknowledge the original outbox first')
            raw, _ = self.regular(self.directory / 'captured.json', private=True, maximum=8192)
            captured = json.loads(raw)
            model, device = self.identity()
            if (set(captured) != {'device_id', 'events'} or captured['device_id'] != device
                    or not isinstance(captured['events'], list) or not 1 <= len(captured['events']) <= 8):
                raise ValueError('Original fixture event batch required')
            with (self.directory / 'replay-requested').open('xb') as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(b'One deliberate exact replay after normal acknowledgement\n')
                output.flush()
                os.fsync(output.fileno())
            revoked = self.send(model.findtext('console_url'), model.findtext('device_secret'), device, captured['events'])
            if revoked is not False:
                raise ValueError('Active original fixture identity required')
            return {'replayed': True, 'event_count': len(captured['events'])}


def main(arguments):
    try:
        if len(arguments) != 2 or arguments[0] not in ('failure', 'restore', 'pending', 'replay', 'recover'):
            raise ValueError('Known fixture action and nonce required')
        boundary(arguments[1], require_route=arguments[0] != 'restore')
        result = getattr(Fixture(), arguments[0])()
        print(json.dumps(result))
        return 0
    except Exception:
        print(json.dumps({'success': False, 'fixture_phase': 'reconcile_failure_fixture'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
