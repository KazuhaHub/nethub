"""Exercise independent native verification without installing trust or sending reports."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'agents/opnsense/plugin/src/usr/local/opnsense/scripts/nethub-agent'))
from certificate_chain import _certificate
from protocol import ProtocolError
import relay_trust as CLIENT
from relay_trust_protocol import applied_request, applied_response

NOW = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
LAYOUT = '%Y-%m-%dT%H:%M:%S.%fZ'


def example(name='relay-trust-settings-response'):
    return json.loads((ROOT/'proto/examples/valid'/(name+'.json')).read_text())


def verify(value, directory, **kwargs):
    return CLIENT.verify_settings(value, example()['device_id'], 'relay.example.com', directory,
                                 now=kwargs.pop('now', NOW), openssl=shutil.which('openssl'), **kwargs)


def bundle(message, ders):
    value = copy.deepcopy(message)
    roots = sorted(ders, key=lambda der: hashlib.sha256(der).hexdigest())
    pem = ''.join('-----BEGIN CERTIFICATE-----\n'+''.join(text[i:i+64]+'\n' for i in range(0, len(text), 64))+'-----END CERTIFICATE-----\n'
                  for text in [base64.b64encode(der).decode('ascii') for der in roots])
    parsed = [_certificate(der) for der in roots]
    value['desired'].update(ca_pem=pem, bundle_fingerprint=hashlib.sha256(('nethub-relay-trust-v1:'+pem).encode()).hexdigest(),
        not_before=max(c['before'] for c in parsed).strftime(LAYOUT), valid_until=min(c['after'] for c in parsed).strftime(LAYOUT))
    return value


def test_public_example_is_independently_verified_and_detached(tmp_path):
    value = example()
    value['future'] = True
    value['desired']['future'] = True
    expected = example()
    assert verify(value, tmp_path) == expected
    result = verify(value, tmp_path)
    result['desired']['generation'] = 2
    assert value['desired']['generation'] == 1
    assert list(tmp_path.iterdir()) == []
    assert verify(expected, tmp_path, previous=expected['desired']) == expected


def test_pending_does_not_erase_previous_trust(tmp_path):
    value = example('relay-trust-settings-pending')
    assert verify(value, tmp_path) == value
    with pytest.raises(ProtocolError):
        verify(value, tmp_path, previous=example()['desired'])


@pytest.mark.parametrize('field,value', [
    ('agent_protocol_version', '1.4.99'), ('agent_protocol_version', '2.5.0'), ('agent_protocol_version', None),
    ('device_id', '22222222-2222-4222-8222-222222222222'), ('desired', False), ('desired', []),
])
def test_wrong_response_identity_is_rejected(tmp_path, field, value):
    message = example(); message[field] = value
    with pytest.raises(ProtocolError, match='Invalid relay trust'):
        verify(message, tmp_path)


@pytest.mark.parametrize('field,value', [
    ('generation', True), ('generation', 0), ('generation', 2147483648), ('generation', 1.5),
    ('generation_id', '00000000-0000-0000-0000-000000000000'), ('server_name', 'other.example.com'),
    ('bundle_fingerprint', '0'*64), ('ca_pem', ''), ('ca_pem', 'PRIVATE KEY'),
    ('published_at', '2026-10-20T00:00:00Z'), ('not_before', '2026-01-01T00:00:00.000001Z'),
    ('valid_until', '2035-01-01T00:00:00.000000Z'), ('published_at', '2036-01-01T00:00:00.000000Z'),
])
def test_metadata_and_public_content_must_agree(tmp_path, field, value):
    message = example(); message['desired'][field] = value
    with pytest.raises(ProtocolError):
        verify(message, tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('instant', [datetime(2025, 12, 31, tzinfo=timezone.utc),
                                  datetime(2036, 1, 1, tzinfo=timezone.utc)])
def test_effective_window_is_half_open(tmp_path, instant):
    with pytest.raises(ProtocolError):
        verify(example(), tmp_path, now=instant)


@pytest.mark.parametrize('change', ['lower', 'same_changed', 'reused_id'])
def test_epoch_cannot_rollback_or_change_identity(tmp_path, change):
    value = example(); previous = copy.deepcopy(value['desired'])
    if change == 'lower':
        previous['generation'] = 2
    elif change == 'same_changed':
        value['desired']['published_at'] = '2026-10-20T00:00:01.000000Z'
    else:
        value['desired']['generation'] = 2
    with pytest.raises(ProtocolError):
        verify(value, tmp_path, previous=previous)


def test_new_epoch_with_same_content_is_valid_without_any_install(tmp_path):
    value = example(); previous = copy.deepcopy(value['desired'])
    value['desired'].update(generation=2, generation_id='55555555-5555-4555-8555-555555555555')
    assert verify(value, tmp_path, previous=previous) == value
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('change', ['duplicate', 'whitespace', 'crlf', 'bad_signature'])
def test_bundle_representation_and_self_signature_are_enforced(tmp_path, change):
    value = example(); pem = value['desired']['ca_pem']
    if change == 'duplicate':
        pem += pem
    elif change == 'whitespace':
        pem = '\n'+pem
    elif change == 'crlf':
        pem = pem.replace('\n', '\r\n')
    else:
        der = base64.b64decode(''.join(pem.splitlines()[1:-1]))
        value = bundle(value, [der[:-1]+bytes([der[-1] ^ 1])]); pem = value['desired']['ca_pem']
    value['desired'].update(ca_pem=pem, bundle_fingerprint=hashlib.sha256(('nethub-relay-trust-v1:'+pem).encode()).hexdigest())
    with pytest.raises(ProtocolError):
        verify(value, tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('stdout,code', [(b'', 0), (b'Verification failure', 0), (b'certificate: OK', 1)])
def test_native_verifier_requires_exact_positive_evidence(tmp_path, stdout, code):
    with mock.patch.object(CLIENT.subprocess, 'run', return_value=subprocess.CompletedProcess([], code, stdout, b'')):
        with pytest.raises(ProtocolError):
            verify(example(), tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('error', [subprocess.TimeoutExpired('openssl', 5), OSError('private child failure')])
def test_native_verifier_failure_is_fixed_and_scratch_is_removed(tmp_path, error):
    with mock.patch.object(CLIENT.subprocess, 'run', side_effect=error):
        with pytest.raises(ProtocolError, match='^Invalid relay trust response$'):
            verify(example(), tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_application_receipt_matches_exact_report_and_server_version():
    value = example('relay-trust-applied-response')
    request = applied_request(value['device_id'], value['generation_id'], value['generation'], value['bundle_fingerprint'])
    value['agent_protocol_version'] = '1.6.0'
    assert applied_response(value, request) == value
    for field, wrong in [('accepted', 1), ('generation', True), ('generation', 1.0), ('generation', 2), ('generation_id', '55555555-5555-4555-8555-555555555555'),
                         ('bundle_fingerprint', '0'*64), ('accepted_at', '2026-10-20T00:00:00Z')]:
        changed = dict(value); changed[field] = wrong
        with pytest.raises(ProtocolError):
            applied_response(changed, request)


@pytest.fixture
def authority(tmp_path):
    directory = tmp_path/'fixture'; directory.mkdir(mode=0o700)
    binary = shutil.which('openssl')

    def create(index, constraints='critical,CA:TRUE', usage='critical,keyCertSign,cRLSign', extra=None, pss_hash=None, pss_options=()):
        path = directory/('root'+str(index)+'.pem')
        args = [binary, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
                '-days', '2', '-subj', '/CN=Private relay trust fixture', '-keyout', str(directory/('key'+str(index))),
                '-out', str(path), '-addext', 'basicConstraints='+constraints, '-addext', 'keyUsage='+usage]
        if extra:
            for oid, specification in extra.items():
                args.extend(['-addext', oid+'='+specification])
        if pss_hash:
            start = args.index('ec')
            args[start:start+3] = ['rsa:2048']
            # OpenSSL releases differ in their default PSS salt length.
            args.extend(['-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:digest',
                         '-sigopt', 'rsa_mgf1_md:'+pss_hash, '-'+pss_hash])
            for option in pss_options:
                args.extend(['-sigopt', option])
        result = subprocess.run(args, capture_output=True, timeout=5)
        assert result.returncode == 0, 'Private root fixture creation failed'
        pem = path.read_text()
        return base64.b64decode(''.join(pem.splitlines()[1:-1]))
    return create


def test_actual_two_root_overlap_is_canonical_and_both_roots_verified(tmp_path, authority):
    value = bundle(example(), [authority(1), authority(2)])
    now = datetime.now(timezone.utc)
    value['desired']['published_at'] = now.strftime(LAYOUT)
    scratch = tmp_path/'scratch'; scratch.mkdir(mode=0o700)
    assert verify(value, scratch, now=now) == value
    blocks = list(CLIENT._PEM.finditer(value['desired']['ca_pem']))
    value['desired']['ca_pem'] = blocks[1].group()+blocks[0].group()
    value['desired']['bundle_fingerprint'] = hashlib.sha256(('nethub-relay-trust-v1:'+value['desired']['ca_pem']).encode()).hexdigest()
    with pytest.raises(ProtocolError):
        verify(value, scratch, now=now)
    assert list(scratch.iterdir()) == []


def test_invalid_member_cannot_hide_in_an_otherwise_valid_overlap(tmp_path, authority):
    valid, broken = authority(1), authority(2)
    broken = broken[:-1]+bytes([broken[-1] ^ 1])
    value = bundle(example(), [valid, broken])
    now = datetime.now(timezone.utc)
    value['desired']['published_at'] = now.strftime(LAYOUT)
    scratch = tmp_path/'scratch'; scratch.mkdir(mode=0o700)
    with pytest.raises(ProtocolError):
        verify(value, scratch, now=now)
    assert list(scratch.iterdir()) == []


def test_ambient_openssl_trust_and_config_are_excluded(tmp_path):
    real = CLIENT.subprocess.run
    with mock.patch.dict(CLIENT.os.environ, {'SSL_CERT_FILE': 'unused-private-path', 'OPENSSL_CONF': 'unused-config'}):
        with mock.patch.object(CLIENT.subprocess, 'run', wraps=real) as called:
            assert verify(example(), tmp_path) == example()
    env = called.call_args.kwargs['env']
    assert 'SSL_CERT_FILE' not in env and 'OPENSSL_CONF' not in env
    assert all(flag in called.call_args.args[0] for flag in ('-no-CAfile', '-no-CApath', '-no-CAstore', '-check_ss_sig'))


@pytest.mark.parametrize('kwargs', [{'constraints': 'critical,CA:FALSE'}, {'usage': 'critical,digitalSignature'},
                                   {'extra': {'1.2.3.4': 'critical,DER:01:01:ff'}}])
def test_self_signed_leaf_nonsigning_ca_and_unknown_critical_are_refused(tmp_path, authority, kwargs):
    value = bundle(example(), [authority(1, **kwargs)])
    now = datetime.now(timezone.utc)
    value['desired']['published_at'] = now.strftime(LAYOUT)
    scratch = tmp_path/'scratch'; scratch.mkdir(mode=0o700)
    with pytest.raises(ProtocolError):
        verify(value, scratch, now=now)
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize('digest,options,accepted', [('sha256', (), True), ('sha384', (), True), ('sha512', (), True),
    ('sha1', (), False), ('sha256', ('rsa_mgf1_md:sha1',), False), ('sha256', ('rsa_pss_saltlen:20',), False)])
def test_actual_pss_parameters_cannot_default_to_weak_hash(tmp_path, authority, digest, options, accepted):
    value = bundle(example(), [authority(1, pss_hash=digest, pss_options=options)])
    now = datetime.now(timezone.utc)
    value['desired']['published_at'] = now.strftime(LAYOUT)
    scratch = tmp_path/'scratch'; scratch.mkdir(mode=0o700)
    if accepted:
        assert verify(value, scratch, now=now) == value
    else:
        with pytest.raises(ProtocolError):
            verify(value, scratch, now=now)
    assert list(scratch.iterdir()) == []
