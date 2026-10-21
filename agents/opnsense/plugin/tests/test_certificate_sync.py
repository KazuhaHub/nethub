"""Exercise original-CSR recovery, independent trust and monotonic public staging."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from unittest import mock

import pytest

from test_certificate_chain import chain, DEVICE, HOST, LAYOUT
from certificate_chain import CertificateChainError
from certificate_key import CertificateKeyError, KeyStore
from certificate_sync import CertificateSynchronizer, CertificateSyncError
from protocol import ProtocolError


def synchronize(case, pending=False, original=True):
    sync = CertificateSynchronizer(case.key, case.verify)
    value = case.issue()
    initial = {name: copy.deepcopy(field) for name, field in value.items() if name != 'issued'}
    if not original:
        initial['request'] = None
    calls = []

    def submit(origin, secret, device, subdomain, fingerprint, csr, context=None):
        calls.append(csr)
        accepted = copy.deepcopy(initial)
        accepted['request'] = copy.deepcopy(case.original)
        accepted['request']['csr_der'] = csr
        accepted['request']['csr_fingerprint'] = hashlib.sha256(base64.b64decode(csr)).hexdigest()
        value['request'] = accepted['request']
        return accepted

    if pending:
        value['issued'] = None
    with mock.patch('certificate_sync.request_settings', return_value=initial), \
            mock.patch('certificate_sync.submit_request', side_effect=submit), \
            mock.patch('certificate_sync.request_issued', side_effect=lambda *args, **kwargs: value):
        result = sync.sync('https://console.example.test', 'private-fixture-secret', DEVICE, HOST.split('.')[0])
    return sync, value, result, calls


@pytest.mark.parametrize('original', [True, False])
def test_actual_csr_signature_and_chain_are_checked_before_public_staging(chain, original):
    before = {p.name: p.read_bytes() for p in chain.key.directory.iterdir()}
    sync, value, result, calls = synchronize(chain, original=original)
    assert result['success'] and result['phase'] == 'verified'
    assert json.loads(sync.path.read_bytes()) == value
    assert sync.path.read_bytes() == KeyStore._encoded(value)
    assert calls == [value['request']['csr_der']]
    if original:
        assert calls == [chain.original['csr_der']]
    assert before == {p.name: p.read_bytes() for p in chain.key.directory.iterdir()}
    assert b'PRIVATE KEY' not in sync.path.read_bytes()
    assert 'private-fixture-secret' not in json.dumps(result)
    if os.name != 'nt':
        assert sync.path.stat().st_mode & 0o777 == 0o600
    assert not list(chain.root.glob('.gui-certificate-*'))


def test_pending_retains_current_generation_and_key(chain):
    sync, value, _, _ = synchronize(chain)
    before = sync.path.read_bytes()
    _, _, result, _ = synchronize(chain, pending=True)
    assert result['phase'] == 'pending' and sync.path.read_bytes() == before


def test_same_generation_is_idempotent_and_regressions_are_refused(chain):
    sync, value, _, _ = synchronize(chain)
    before = sync.path.stat()
    sync._stage(value)
    assert (sync.path.stat().st_ino, sync.path.stat().st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    newer = copy.deepcopy(value)
    newer['issued']['generation'] = 2
    newer['issued']['generation_id'] = '456789ab-4567-4567-4567-456789abcdef'
    sync._stage(newer)
    raw = sync.path.read_bytes()
    with pytest.raises(ValueError):
        sync._stage(value)
    changed = copy.deepcopy(newer)
    changed['issued']['generation_id'] = value['issued']['generation_id']
    with pytest.raises(ValueError):
        sync._stage(changed)
    reused = copy.deepcopy(newer)
    reused['issued']['generation'] = 3
    with pytest.raises(ValueError):
        sync._stage(reused)
    assert sync.path.read_bytes() == raw


def test_expired_public_staging_metadata_does_not_block_verified_renewal(chain):
    sync, value, _, _ = synchronize(chain)
    previous = copy.deepcopy(value)
    issued = previous['issued']
    now = datetime.now(timezone.utc)
    # The staging reader validates only the old record's identity and ordering.
    # Current material still passes the independent verifier before _stage.
    for name, hours in [('not_before', 48), ('not_after', 24), ('valid_until', 24), ('renew_after', 36)]:
        issued[name] = (now - timedelta(hours=hours)).strftime(LAYOUT)
    sync.path.write_bytes(KeyStore._encoded(previous))
    renewed = chain.verify.verify(value, DEVICE, HOST.split('.')[0], chain.original)
    renewed['issued']['generation'] = 2
    renewed['issued']['generation_id'] = '456789ab-4567-4567-4567-456789abcdef'
    sync._stage(renewed)
    assert json.loads(sync.path.read_bytes())['issued']['generation'] == 2


@pytest.mark.parametrize('failure', ['network', 'trust', 'replace'])
def test_failure_preserves_current_candidate_and_uses_fixed_diagnostic(chain, failure):
    sync, value, _, _ = synchronize(chain)
    raw = sync.path.read_bytes()
    initial = {name: field for name, field in value.items() if name != 'issued'}
    target, error = {
        'network': ('certificate_sync.request_settings', ProtocolError('private remote content')),
        'trust': ('certificate_chain.ChainVerifier.verify', CertificateChainError('private chain content')),
        'replace': ('certificate_sync.os.replace', OSError('private filesystem content')),
    }[failure]
    newer = copy.deepcopy(value)
    newer['issued']['generation'] = 2
    newer['issued']['generation_id'] = '456789ab-4567-4567-4567-456789abcdef'
    with mock.patch('certificate_sync.request_settings', return_value=initial), \
            mock.patch('certificate_sync.submit_request', return_value=initial), \
            mock.patch('certificate_sync.request_issued', return_value=newer), \
            mock.patch(target, side_effect=error):
        with pytest.raises(CertificateSyncError, match='^GUI certificate synchronization failed; tunnel and native GUI settings were retained$'):
            sync.sync('https://console.example.test', 'private-fixture-secret', DEVICE, HOST.split('.')[0])
    assert sync.path.read_bytes() == raw
    assert not list(chain.root.glob('.gui-certificate-*'))


def test_public_runtime_cleanup_is_idempotent_and_preserves_key_and_native_store(chain):
    sync, _, _, _ = synchronize(chain)
    before = {p.name: p.read_bytes() for p in chain.key.directory.iterdir()}
    native = chain.root / 'native-store'
    native.write_bytes(b'Independent native certificate and certref')
    sync.forget()
    sync.forget()
    assert not sync.path.exists() and not sync.requests.directory.exists()
    assert before == {p.name: p.read_bytes() for p in chain.key.directory.iterdir()}
    assert native.read_bytes() == b'Independent native certificate and certref'


def test_unknown_request_artifact_blocks_cleanup(chain):
    sync, _, _, _ = synchronize(chain)
    (sync.requests.directory / 'unknown').write_text('Retain for local review')
    with pytest.raises(CertificateKeyError):
        sync.forget()
    assert sync.path.exists() and (chain.key.directory / 'key.pem').exists()
