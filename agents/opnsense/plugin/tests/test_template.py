"""Check the actual template's TLS, heartbeat, and proxy structure."""
from pathlib import Path
import tomllib

import jinja2
import pytest

TEMPLATE = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/service/templates/OPNsense/NetHubAgent/frpc.toml.j2'


@pytest.mark.parametrize('port,expected', [('', 443), ('9443', 9443)])
def test_enabled_template(port, expected):
    context = {'OPNsense': {'NetHubAgent': {
        'enabled': '1', 'server_addr': 'relay.example.com', 'server_port': '7000',
        'frp_token': 'test-only', 'device_id': 'device-test',
        'domain_claim': 'test.claim', 'subdomain': 'device-test'}},
        'system': {'webgui': {'port': port}}}
    text = jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(TEMPLATE.read_text()).render(**context)
    config = tomllib.loads(text)
    assert config['loginFailExit'] is False
    assert config['transport']['heartbeatInterval'] == 10
    assert config['transport']['heartbeatTimeout'] == 30
    assert config['transport']['tls'] == {
        'enable': True, 'trustedCaFile': '/usr/local/etc/nethub-agent/relay-ca.pem',
        'serverName': 'relay.example.com'}
    assert config['metadatas']['device_id'] == 'device-test'
    assert config['proxies'] == [{'name': 'nethub-webgui', 'type': 'https',
                                  'localIP': '127.0.0.1', 'localPort': expected,
                                  'subdomain': 'device-test'}]
    assert 'webServer' not in config
    assert 'customDomains' not in text


def test_disabled_template_requires_no_credentials():
    text = jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(TEMPLATE.read_text()).render(
        OPNsense={'NetHubAgent': {'enabled': '0'}})
    assert tomllib.loads(text) == {}
