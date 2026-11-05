"""A failed installed case must not bypass retirement or mask its first error."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/trust_publication_recovery.py'
sys.path.insert(0, str(SOURCE.parent))
try:
    SPEC = importlib.util.spec_from_file_location('native_publication_fault', SOURCE)
    SUITE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(SUITE)
finally:
    sys.path.pop(0)


def test_body_failure_is_not_masked_by_an_invalid_retirement(tmp_path, monkeypatch):
    public = tmp_path / 'deployment/secrets/issuer/ca.pem'
    public.parent.mkdir(parents=True)
    public.write_bytes(b'original public fixture')
    expected = hashlib.sha256(b'fixture DER').hexdigest()
    metadata = {'previous_root_fingerprint': expected, 'next_root_fingerprint': 'f' * 64}
    publication = SUITE.Publication(tmp_path, 'fixture', tmp_path)
    publication.current = lambda: {'state': 'current', 'generation': 1, 'root_fingerprints': [expected]}
    phases = []

    def publish(_path, _previous, phase):
        phases.append(phase)
        if phase == 'original_publication':
            raise RuntimeError('retirement must not hide the initial failure')
        return {'generation': 2, 'root_fingerprints': [expected, 'f' * 64]}

    def invoke(arguments, _label, **_options):
        if arguments[0] == 'openssl':
            return b'fixture DER'
        action = arguments[3]
        if action == 'prepare':
            candidate = tmp_path / 'native-publication/candidate'
            candidate.mkdir()
            (candidate / 'ca.pem').write_bytes(b'successor public fixture')
            return json.dumps({'candidate': metadata}).encode()
        assert action in ('backup', 'verify-backup')
        return json.dumps({'candidate': metadata, 'backup_verified': True}).encode()

    publication.publish = publish
    monkeypatch.setattr(SUITE, 'invoke', invoke)
    with pytest.raises(RuntimeError, match='initial fixture failure'):
        with publication.overlap():
            raise RuntimeError('initial fixture failure')
    assert phases == ['overlap_publication']


def test_unknown_active_device_is_refused_before_any_reference_report(tmp_path):
    work = tmp_path / 'relay-test'
    work.mkdir()
    identities = [f'{letter * 8}-{letter * 4}-4{letter * 3}-8{letter * 3}-{letter * 12}' for letter in 'abcd']
    for index, identity in enumerate(identities[:2]):
        (work / ('assignment' + str(index) + '.json')).write_text(json.dumps({'device_id': identity}))
    def forbidden(*_args, **_kwargs):
        pytest.fail('An unknown active inventory must not reach report or client mutation')
    with pytest.raises(SUITE.GuestError, match='exact active fixture inventory'):
        SUITE.synchronize_references(tmp_path, {}, forbidden, lambda _query: '\n'.join(identities),
                                     identities[2], identities[1], forbidden)


class TrustGuest:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.calls = 0

    def ssh(self, script, label, timeout):
        assert script == '/usr/local/sbin/configctl nethub-agent trust\n'
        assert timeout == 100
        self.calls += 1
        return next(self.replies)


def test_empty_scheduled_action_is_not_accepted_as_execution(monkeypatch):
    sleeps = []
    monkeypatch.setattr(SUITE.time, 'sleep', sleeps.append)
    expected = {'success': True, 'action': 'trust', 'phase': 'rotation_pending', 'confirmed': False}
    guest = TrustGuest([b'', b'\n', json.dumps(expected).encode()])
    assert SUITE.native_trust(guest) == expected
    assert guest.calls == 3 and sleeps == [2, 2]


def test_repeated_empty_scheduled_action_has_a_fixed_bound(monkeypatch):
    sleeps = []
    monkeypatch.setattr(SUITE.time, 'sleep', sleeps.append)
    guest = TrustGuest([b''] * 4)
    with pytest.raises(SUITE.GuestError, match='no result after bounded retries'):
        SUITE.native_trust(guest)
    assert guest.calls == 4 and sleeps == [2, 2, 2]


@pytest.mark.parametrize('reply', [b'private malformed output', b'[]', b'{"success":false,"action":"trust"}'])
def test_nonempty_invalid_or_failed_action_is_not_retried(reply):
    guest = TrustGuest([reply])
    with pytest.raises(SUITE.GuestError) as error:
        SUITE.native_trust(guest)
    assert guest.calls == 1
    assert 'private malformed output' not in str(error.value)
