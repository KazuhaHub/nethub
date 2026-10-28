"""Exercise durable candidate recovery without appliance configuration writes."""
import base64
import copy
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'agents/opnsense/plugin/src/usr/local/opnsense/scripts/nethub-agent'))
from protocol import ProtocolError
from test_enrollment import https_console
from rotation import RotationError, RotationJournal, validate_rotation_response

ORIGIN = 'https://console.example.com'


@pytest.fixture
def original():
    return json.loads((ROOT / 'proto/examples/valid/enroll-response.json').read_text(encoding='utf-8'))


@pytest.fixture
def journal(tmp_path):
    os.chmod(tmp_path, 0o700)
    return RotationJournal(tmp_path)


def response(original, operation, candidate):
    result = copy.deepcopy(original)
    result.update(agent_protocol_version='1.6.0', operation_id=operation, device_secret=candidate)
    payload, signature = result['domain_claim'].split('.')
    claim = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    claim['issued_at'] = '2026-10-28T00:00:00.000001Z'
    payload = base64.urlsafe_b64encode(json.dumps(claim, separators=(',', ':')).encode()).decode().rstrip('=')
    result['domain_claim'] = payload + '.' + signature
    return result


def test_candidate_is_durable_before_network_and_reused_after_lost_response(journal, original):
    committed = {}
    def lost(origin, path, body, **kwargs):
        saved = RotationJournal(journal.directory)._read()
        assert saved['phase'] == 'prepared'
        assert body['operation_id'] == saved['operation_id']
        assert body['replacement_secret'] == saved['candidate']
        committed.update(response(original, saved['operation_id'], saved['candidate']))
        raise ProtocolError('synthetic lost response')
    with pytest.raises(RotationError):
        journal.request(ORIGIN, original, transport=lost)
    retained = journal.path.read_bytes()
    calls = []
    def recover(origin, path, body, **kwargs):
        calls.append(kwargs['secret'])
        assert journal.path.read_bytes() == retained
        if kwargs['secret'] == original['device_secret']:
            raise ProtocolError('synthetic old bearer refusal')
        assert kwargs['secret'] == committed['device_secret']
        return committed
    result = RotationJournal(journal.directory).request(ORIGIN, original, transport=recover)
    assert calls == [original['device_secret'], result['device_secret']]
    assert journal._read()['phase'] == 'received'
    def unavailable(*args, **kwargs):
        pytest.fail('saved assignment retry must not rotate again')
    assert journal.request(ORIGIN, original, transport=unavailable) == result
    assert journal.prepare(ORIGIN, result)['assignment'] == result
    with pytest.raises(RotationError):
        journal.complete(ORIGIN, original)
    assert journal.path.exists()
    journal.complete(ORIGIN, result)
    assert not journal.path.exists()


def test_changed_origin_or_model_cannot_adopt_pending_candidate(journal, original):
    saved = journal.prepare(ORIGIN, original)
    before = journal.path.read_bytes()
    changed = dict(original, device_secret='B' * 42 + 'A')
    for origin, model in [('https://other.example.com', original), (ORIGIN, changed)]:
        with pytest.raises(RotationError):
            journal.prepare(origin, model)
        assert journal.path.read_bytes() == before
    assert journal.prepare(ORIGIN, original)['operation_id'] == saved['operation_id']


@pytest.mark.parametrize('field,value', [
    ('operation_id', '44444444-4444-4444-8444-444444444444'),
    ('device_secret', 'A' * 43), ('agent_protocol_version', '1.5.0'),
    ('device_id', '44444444-4444-4444-8444-444444444444'), ('subdomain', 'other123'),
])
def test_mismatched_response_retains_candidate(journal, original, field, value):
    saved = journal.prepare(ORIGIN, original)
    before = journal.path.read_bytes()
    reply = response(original, saved['operation_id'], saved['candidate'])
    reply[field] = value
    with pytest.raises((RotationError, ProtocolError)):
        journal.request(ORIGIN, original, transport=lambda *args, **kwargs: reply)
    assert journal.path.read_bytes() == before


def test_unchanged_claim_and_ambiguous_journal_cannot_pass(journal, original):
    saved = journal.prepare(ORIGIN, original)
    reply = dict(original, operation_id=saved['operation_id'], device_secret=saved['candidate'], agent_protocol_version='1.6.0')
    with pytest.raises(RotationError):
        validate_rotation_response(reply, original, saved['operation_id'], saved['candidate'])
    raw = journal.path.read_bytes()
    journal.path.write_bytes(raw.replace(b'{', b'{"version":1,', 1))
    with pytest.raises(RotationError):
        journal.prepare(ORIGIN, original)


def test_failed_candidate_persistence_never_reaches_network(journal, original, monkeypatch):
    def refuse(value):
        raise OSError('synthetic storage failure')
    monkeypatch.setattr(journal, '_write', refuse)
    def network(*args, **kwargs):
        pytest.fail('network used before durable candidate persistence')
    with pytest.raises(RotationError):
        journal.request(ORIGIN, original, transport=network)


def test_failed_response_persistence_retries_the_same_committed_candidate(journal, original, monkeypatch):
    saved = journal.prepare(ORIGIN, original)
    before = journal.path.read_bytes()
    reply = response(original, saved['operation_id'], saved['candidate'])
    def refuse(value):
        raise OSError('synthetic response storage failure')
    monkeypatch.setattr(journal, '_write', refuse)
    with pytest.raises(RotationError):
        journal.request(ORIGIN, original, transport=lambda *args, **kwargs: reply)
    assert journal.path.read_bytes() == before
    recovered = RotationJournal(journal.directory).request(ORIGIN, original, transport=lambda *args, **kwargs: reply)
    assert recovered['device_secret'] == saved['candidate']


def test_unknown_commit_removal_uses_only_the_bound_candidate(journal, original):
    saved = journal.prepare(ORIGIN, original)
    before = journal.path.read_bytes()
    assert journal.removal_candidate(ORIGIN, original['device_id'], original['device_secret']) == saved['candidate']
    assert journal.removal_candidate(ORIGIN, original['device_id'], saved['candidate']) == saved['candidate']
    for origin, device, secret in [
        ('https://other.example.com', original['device_id'], original['device_secret']),
        (ORIGIN, '44444444-4444-4444-8444-444444444444', original['device_secret']),
        (ORIGIN, original['device_id'], 'B' * 42 + 'A'),
    ]:
        with pytest.raises(RotationError):
            journal.removal_candidate(origin, device, secret)
        assert journal.path.read_bytes() == before


def test_removal_cleanup_requires_exact_confirmed_device(journal, original):
    journal.prepare(ORIGIN, original)
    with pytest.raises(RotationError):
        journal.forget_revoked('44444444-4444-4444-8444-444444444444')
    assert journal.path.exists()
    journal.forget_revoked(original['device_id'])
    assert not journal.path.exists()


@pytest.mark.skipif(os.name != 'posix', reason='Production POSIX ownership boundary')
def test_public_or_linked_journal_is_never_adopted(journal, original):
    journal.prepare(ORIGIN, original)
    journal.path.chmod(0o644)
    with pytest.raises(RotationError):
        journal.prepare(ORIGIN, original)
    journal.path.chmod(0o600)
    alternate = journal.directory / 'other.json'
    journal.path.rename(alternate)
    journal.path.symlink_to(alternate)
    with pytest.raises(RotationError):
        journal.prepare(ORIGIN, original)


def test_pending_phase_validates_prepared_and_received_without_private_output(journal, original):
    journal.prepare(ORIGIN, original)
    assert journal.pending_phase() == 'prepared'
    journal.request(ORIGIN, original, transport=lambda origin, path, body, **kwargs:
                    response(original, body['operation_id'], body['replacement_secret']))
    assert journal.pending_phase() == 'received'
    journal.path.write_text('{}')
    with pytest.raises(RotationError, match='retain its journal'):
        journal.pending_phase()


def test_definitive_old_credential_trust_refusal_releases_only_uncommitted_journal(journal, original):
    from protocol import RotationTrustChanged
    calls = []
    def conflict(origin, path, body, **kwargs):
        import hashlib
        saved = journal._read()
        assert saved['phase'] == 'prepared'
        assert body['expected_relay_ca_sha256'] == hashlib.sha256(original['relay_ca_pem'].encode('ascii')).hexdigest()
        calls.append(kwargs['secret'])
        raise RotationTrustChanged('remote private message')
    with pytest.raises(RotationError, match='^Relay trust changed; synchronize trust and retry rotation$'):
        journal.request(ORIGIN, original, transport=conflict)
    assert calls == [original['device_secret']] and not journal.path.exists()


def test_candidate_attempt_trust_error_cannot_discard_unknown_commit(journal, original):
    from protocol import RotationTrustChanged
    journal.prepare(ORIGIN, original)
    retained = journal.path.read_bytes()
    def ambiguous(origin, path, body, **kwargs):
        if kwargs['secret'] == original['device_secret']:
            raise ProtocolError('ambiguous old-credential response')
        raise RotationTrustChanged('unexpected candidate refusal')
    with pytest.raises(RotationError, match='retain the journal'):
        journal.request(ORIGIN, original, transport=ambiguous)
    assert journal.path.read_bytes() == retained


def test_changed_trust_in_response_never_saves_a_conflicting_assignment(journal, original, https_console):
    def changed(origin, path, body, **kwargs):
        value = response(original, body['operation_id'], body['replacement_secret'])
        # A genuinely valid replacement root still cannot change the pinned
        # trust of an operation retained against the original native model.
        from enrollment import validate_response
        value['relay_ca_pem'] = https_console[3]['ca_pem']
        assert value['relay_ca_pem'] != original['relay_ca_pem']
        validate_response({key: item for key, item in value.items() if key != 'operation_id'})
        return value
    with pytest.raises(RotationError):
        journal.request(ORIGIN, original, transport=changed)
    assert journal._read()['phase'] == 'prepared'
