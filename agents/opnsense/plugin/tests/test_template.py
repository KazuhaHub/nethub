"""Check the actual template's TLS, heartbeat, and proxy structure."""
from pathlib import Path
import shutil
import sys
import tomllib

import jinja2
import pytest

TEMPLATE = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/service/templates/OPNsense/NetHubAgent/frpc.toml.j2'


@pytest.mark.parametrize('port,expected', [('', 443), ('9443', 9443)])
@pytest.mark.parametrize('device_id', [
    '11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222',
])
def test_enabled_template(port, expected, device_id):
    context = {'OPNsense': {'NetHubAgent': {
        'enabled': '1', 'server_addr': 'relay.example.com', 'server_port': '7000',
        'frp_token': 'test-only', 'device_id': device_id,
        'domain_claim': 'test.claim', 'subdomain': 'abcd1234'}},
        'system': {'webgui': {'port': port}}}
    text = jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(TEMPLATE.read_text()).render(**context)
    config = tomllib.loads(text)
    assert config['loginFailExit'] is False
    assert config['transport']['heartbeatInterval'] == 10
    assert config['transport']['heartbeatTimeout'] == 30
    assert config['transport']['tls'] == {
        'enable': True, 'trustedCaFile': '/usr/local/etc/nethub-agent/relay-ca.pem',
        'serverName': 'relay.example.com'}
    assert config['metadatas']['device_id'] == device_id
    assert config['proxies'] == [{'name': f'nethub-{device_id}-web', 'type': 'https',
                                  'localIP': '127.0.0.1', 'localPort': expected,
                                  'subdomain': 'abcd1234'}]
    assert 'webServer' not in config
    assert 'customDomains' not in text


def test_disabled_template_requires_no_credentials():
    text = jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(TEMPLATE.read_text()).render(
        OPNsense={'NetHubAgent': {'enabled': '0'}})
    assert tomllib.loads(text) == {}


def test_tls_name_is_independent_of_connection_address():
    settings = {'enabled': '1', 'server_addr': 'relay-address.example.com', 'server_name': 'relay-tls.example.com',
                'server_port': '7000', 'frp_token': 'test-only', 'device_id': 'test-device',
                'domain_claim': 'test.claim', 'subdomain': 'test-device'}
    rendered = jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(TEMPLATE.read_text()).render(
        OPNsense={'NetHubAgent': settings}, system={'webgui': {'port': '443'}})
    config = tomllib.loads(rendered)
    assert config['serverAddr'] == settings['server_addr']
    assert config['transport']['tls']['serverName'] == settings['server_name']


@pytest.mark.skipif(not sys.platform.startswith('freebsd'), reason='Requires the native OPNsense template engine')
def test_native_wildcard_boot_reload_skips_candidate_but_explicit_reconcile_renders_it(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend('/usr/local/opnsense/service')
    from modules.template import Template

    templates = tmp_path / 'templates'
    module = templates / 'OPNsense/NetHubAgent'
    module.mkdir(parents=True)
    shutil.copy2(TEMPLATE, module / TEMPLATE.name)
    shutil.copy2(TEMPLATE.with_name('+TARGETS'), module / '+TARGETS')
    output = tmp_path / 'output'
    parent = output / 'usr/local/etc/nethub-agent'
    parent.mkdir(parents=True, mode=0o700)
    engine = Template(target_root_directory=str(output))
    engine._template_dir = str(templates) + '/'
    engine._j2_env.loader = jinja2.FileSystemLoader(str(templates))
    engine.set_config({'OPNsense': {'NetHubAgent': {'enabled': '0'}}})
    candidate = parent / 'frpc.toml.candidate'

    assert engine.generate('*') is None
    assert not candidate.exists()
    assert engine.generate('OPNsense.NetHubAgent') == [str(candidate)]
    assert tomllib.loads(candidate.read_text()) == {}
    assert candidate.stat().st_mode & 0o777 == 0o600
    candidate.write_text('retain a pending candidate')
    assert engine.generate('OPNsense.*') is None
    assert candidate.read_text() == 'retain a pending candidate'
