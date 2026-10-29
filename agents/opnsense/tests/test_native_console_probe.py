"""Do not expose peer names or raw exceptions in uploaded guest diagnostics."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'acceptance/console_probe.py'
SPEC = importlib.util.spec_from_file_location('native_console_probe', SOURCE)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class Connection:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


@pytest.fixture
def network(monkeypatch):
    monkeypatch.setattr(PROBE.socket, 'gethostbyname', lambda _: '10.0.2.100')
    monkeypatch.setattr(PROBE.socket, 'create_connection', lambda *_args, **_kwargs: Connection())
    monkeypatch.setattr(PROBE.ssl, 'create_default_context',
        lambda: SimpleNamespace(wrap_socket=lambda *_args, **_kwargs: Connection()))
    monkeypatch.setattr(PROBE.urllib.request, 'urlopen', lambda *_args, **_kwargs: Connection())


def test_canonical_system_trust_probe_complete(network):
    result = PROBE.probe()
    PROBE.validate_result(result)
    assert result['passed'] is True and result['phase'] == 'complete' and result['http_status'] == 200


@pytest.mark.parametrize('failure', ['dns', 'certificate', 'http'])
def test_failures_return_only_closed_categories(network, monkeypatch, failure):
    def refuse(*_args, **_kwargs):
        if failure == 'dns':
            raise PROBE.socket.gaierror('private-peer-must-not-escape')
        if failure == 'certificate':
            error = PROBE.ssl.SSLCertVerificationError(1, 'private-peer-must-not-escape')
            error.verify_code = 20
            raise error
        raise PROBE.urllib.error.HTTPError('https://private-peer-must-not-escape', 400,
                                           'private-peer-must-not-escape', None, None)

    if failure == 'dns':
        monkeypatch.setattr(PROBE.socket, 'gethostbyname', refuse)
    elif failure == 'certificate':
        monkeypatch.setattr(PROBE.ssl, 'create_default_context', refuse)
    else:
        monkeypatch.setattr(PROBE.urllib.request, 'urlopen', refuse)
    result = PROBE.probe()
    PROBE.validate_result(result)
    assert result['passed'] is False and 'private-peer' not in json.dumps(result)
    assert result['failure'] == {'dns': 'dns_resolution', 'certificate': 'tls_verify', 'http': 'http_status'}[failure]
    if failure == 'certificate':
        assert result['verify_code'] == 20
    if failure == 'http':
        assert result['http_status'] == 400


@pytest.mark.parametrize('field,value', [('phase', 'private-peer-must-not-escape'),
    ('failure', 'private-peer-must-not-escape'), ('http_status', True), ('verify_code', 1001),
    ('unexpected', 'private-peer-must-not-escape')])
def test_unexpected_diagnostic_fields_are_refused(network, field, value):
    result = PROBE.probe()
    result[field] = value
    with pytest.raises(ValueError, match='Unexpected closed console probe result'):
        PROBE.validate_result(result)
